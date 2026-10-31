-- MSMI Supabase account portal schema
-- Run once in Supabase Dashboard > SQL Editor > New query.
-- Passwords are handled by Supabase Auth; never store plaintext passwords here.

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint username_format check (username ~ '^[A-Za-z0-9_]{3,24}$')
);

create unique index if not exists profiles_username_lower_unique
  on public.profiles (lower(username));

alter table public.profiles enable row level security;

drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile"
  on public.profiles for select to authenticated
  using (auth.uid() = id);

drop policy if exists "Users can update own profile" on public.profiles;
create policy "Users can update own profile"
  on public.profiles for update to authenticated
  using (auth.uid() = id) with check (auth.uid() = id);

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
before update on public.profiles
for each row execute procedure public.set_updated_at();

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  requested_username text;
begin
  requested_username := new.raw_user_meta_data ->> 'username';
  if requested_username is null
     or requested_username !~ '^[A-Za-z0-9_]{3,24}$' then
    requested_username := 'user_' || substr(replace(new.id::text, '-', ''), 1, 12);
  end if;
  insert into public.profiles (id, username)
  values (new.id, requested_username);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- No public INSERT policy is needed: the Auth trigger creates each profile.\n\n
-- PRIVATE ONLINE NOTEPAD
-- Each authenticated user has exactly one private notepad row.
create table if not exists public.user_notes (
  user_id uuid primary key references auth.users (id) on delete cascade,
  content text not null default '',
  updated_at timestamptz not null default now()
);

alter table public.user_notes enable row level security;

drop policy if exists "Users can read own note" on public.user_notes;
create policy "Users can read own note"
  on public.user_notes for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists "Users can insert own note" on public.user_notes;
create policy "Users can insert own note"
  on public.user_notes for insert to authenticated
  with check (auth.uid() = user_id);

drop policy if exists "Users can update own note" on public.user_notes;
create policy "Users can update own note"
  on public.user_notes for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

