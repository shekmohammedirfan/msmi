-- MSMI ACCOUNT PORTAL + PRIVATE NOTEPAD + SHARED NOTEPAD + LIVE MESSAGES
-- Run this complete script in Supabase Dashboard > SQL Editor.
-- Safe to re-run. Supabase Auth stores password hashes; never store passwords here.

-- MEMBER PROFILES
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint username_format check (username ~ '^[A-Za-z0-9_]{3,24}$')
);
create unique index if not exists profiles_username_lower_unique on public.profiles(lower(username));
alter table public.profiles enable row level security;
drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile" on public.profiles for select to authenticated using (auth.uid() = id);
drop policy if exists "Users can update own profile" on public.profiles;
create policy "Users can update own profile" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);
grant select, update on public.profiles to authenticated;

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$ begin new.updated_at = now(); return new; end; $$;
drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at before update on public.profiles for each row execute procedure public.set_updated_at();

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
declare requested_username text;
begin
  requested_username := new.raw_user_meta_data ->> 'username';
  if requested_username is null or requested_username !~ '^[A-Za-z0-9_]{3,24}$' then
    requested_username := 'user_' || substr(replace(new.id::text, '-', ''), 1, 12);
  end if;
  insert into public.profiles(id, username) values(new.id, requested_username)
  on conflict (id) do nothing;
  return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

-- PRIVATE NOTEPAD: one private row per signed-in user.
create table if not exists public.user_notes (
  user_id uuid primary key references auth.users(id) on delete cascade,
  content text not null default '',
  updated_at timestamptz not null default now()
);
alter table public.user_notes enable row level security;
drop policy if exists "Users can read own note" on public.user_notes;
create policy "Users can read own note" on public.user_notes for select to authenticated using(auth.uid() = user_id);
drop policy if exists "Users can insert own note" on public.user_notes;
create policy "Users can insert own note" on public.user_notes for insert to authenticated with check(auth.uid() = user_id);
drop policy if exists "Users can update own note" on public.user_notes;
create policy "Users can update own note" on public.user_notes for update to authenticated using(auth.uid() = user_id) with check(auth.uid() = user_id);
grant select, insert, update on public.user_notes to authenticated;

-- PUBLIC NOTEPAD: exactly one shared document (id=1), editable by every authenticated member.
create table if not exists public.shared_notes (
  id smallint primary key check (id = 1),
  content text not null default '',
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);
insert into public.shared_notes(id, content) values(1, '') on conflict(id) do nothing;
alter table public.shared_notes enable row level security;
drop policy if exists "Members can read shared note" on public.shared_notes;
create policy "Members can read shared note" on public.shared_notes for select to authenticated using(true);
drop policy if exists "Members can create shared note" on public.shared_notes;
create policy "Members can create shared note" on public.shared_notes for insert to authenticated with check(id = 1 and updated_by = auth.uid());
drop policy if exists "Members can edit shared note" on public.shared_notes;
create policy "Members can edit shared note" on public.shared_notes for update to authenticated using(true) with check(id = 1 and updated_by = auth.uid());
grant select, insert, update on public.shared_notes to authenticated;

-- PRIVATE IN-APP MESSAGES: recipient is resolved from registered Auth email on the server.
create table if not exists public.user_messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  sender_email text not null,
  recipient_email text not null,
  body text not null check (char_length(body) between 1 and 5000),
  created_at timestamptz not null default now(),
  constraint no_self_message check(sender_id <> recipient_id)
);
create index if not exists user_messages_sender_created_idx on public.user_messages(sender_id, created_at desc);
create index if not exists user_messages_recipient_created_idx on public.user_messages(recipient_id, created_at desc);
alter table public.user_messages enable row level security;
drop policy if exists "Members can read their messages" on public.user_messages;
create policy "Members can read their messages" on public.user_messages for select to authenticated
using(auth.uid() = sender_id or auth.uid() = recipient_id);
drop policy if exists "Members can delete their messages" on public.user_messages;
create policy "Members can delete their messages" on public.user_messages for delete to authenticated
using(auth.uid() = sender_id or auth.uid() = recipient_id);
revoke all on public.user_messages from anon, authenticated;
grant select, delete on public.user_messages to authenticated;

-- RPC avoids exposing auth.users email addresses to browser queries.
create or replace function public.send_message_to_email(p_recipient_email text, p_body text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_sender_id uuid := auth.uid();
  v_sender_email text;
  v_recipient_id uuid;
  v_recipient_email text;
  v_message_id uuid;
begin
  if v_sender_id is null then raise exception 'You must be signed in to send messages.'; end if;
  if p_recipient_email is null or length(trim(p_recipient_email)) = 0 then raise exception 'Recipient email is required.'; end if;
  if p_body is null or length(trim(p_body)) = 0 or char_length(p_body) > 5000 then raise exception 'Message must contain 1 to 5000 characters.'; end if;

  select lower(email) into v_sender_email from auth.users where id = v_sender_id;
  select id, lower(email) into v_recipient_id, v_recipient_email
  from auth.users where lower(email) = lower(trim(p_recipient_email)) and email_confirmed_at is not null limit 1;
  if v_recipient_id is null then raise exception 'No confirmed MSMI account was found for that email address.'; end if;
  if v_recipient_id = v_sender_id then raise exception 'You cannot send a message to your own account.'; end if;

  insert into public.user_messages(sender_id, recipient_id, sender_email, recipient_email, body)
  values(v_sender_id, v_recipient_id, coalesce(v_sender_email,''), v_recipient_email, trim(p_body))
  returning id into v_message_id;
  return jsonb_build_object('ok', true, 'message_id', v_message_id);
end;
$$;
revoke all on function public.send_message_to_email(text,text) from public, anon;
grant execute on function public.send_message_to_email(text,text) to authenticated;

-- Enable Supabase Realtime for live inbox updates (safe if already enabled).
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='user_messages') then
    alter publication supabase_realtime add table public.user_messages;
  end if;
end $$;

-- Refresh PostgREST's schema cache so the new tables/RPC are immediately visible.
notify pgrst, 'reload schema';
