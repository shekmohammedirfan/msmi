-- MSMI portal schema upgrade: rich notes, shared announcement, member search,
-- admin read-only oversight of private notes/messages, and secure password-reset workflow.
-- Run this AFTER (or instead of) the previous MSMI_schema.sql in Supabase SQL Editor.
-- IMPORTANT: passwords are managed by Supabase Auth and are NEVER exposed by this script.

-- Existing tables expected from the previous MSMI schema:
-- public.profiles, public.user_notes, public.shared_notes, public.user_messages

create table if not exists public.admin_announcements (
  id smallint primary key check (id = 1),
  content text not null default '',
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);
insert into public.admin_announcements(id,content) values(1,'Welcome to MSMI.') on conflict(id) do nothing;
alter table public.admin_announcements enable row level security;
drop policy if exists "Authenticated members can read admin announcement" on public.admin_announcements;
create policy "Authenticated members can read admin announcement"
  on public.admin_announcements for select to authenticated using (true);
drop policy if exists "Only MSMI admin can insert announcement" on public.admin_announcements;
create policy "Only MSMI admin can insert announcement"
  on public.admin_announcements for insert to authenticated
  with check (lower(coalesce(auth.jwt()->>'email','')) = 'shekmohammedirfan412@gmail.com' and updated_by = auth.uid());
drop policy if exists "Only MSMI admin can update announcement" on public.admin_announcements;
create policy "Only MSMI admin can update announcement"
  on public.admin_announcements for update to authenticated
  using (lower(coalesce(auth.jwt()->>'email','')) = 'shekmohammedirfan412@gmail.com')
  with check (lower(coalesce(auth.jwt()->>'email','')) = 'shekmohammedirfan412@gmail.com' and updated_by = auth.uid());
grant select, insert, update on public.admin_announcements to authenticated;

-- Search suggestions for the recipient field. Returns only matching email + username,
-- never password data or other account secrets. A short query is required.
create or replace function public.search_members_for_message(p_query text)
returns table(email text, username text)
language plpgsql
security definer
set search_path = ''
as $$
declare q text := lower(trim(coalesce(p_query,'')));
begin
  if auth.uid() is null then raise exception 'Sign in required.'; end if;
  if length(q) < 2 then return; end if;
  return query
    select lower(u.email)::text, p.username::text
    from auth.users u
    left join public.profiles p on p.id = u.id
    where u.email is not null
      and u.id <> auth.uid()
      and (lower(u.email) like '%' || q || '%' or lower(coalesce(p.username,'')) like '%' || q || '%')
    order by lower(u.email)
    limit 8;
end;
$$;
revoke all on function public.search_members_for_message(text) from public, anon;
grant execute on function public.search_members_for_message(text) to authenticated;

-- Admin-only portal overview. SECURITY DEFINER bypasses normal table RLS, but the
-- function checks the verified JWT email on the server before returning anything.
-- It includes member profiles, private note contents, and private message contents,
-- as explicitly requested for the MSMI admin. It deliberately excludes passwords.
create or replace function public.admin_get_portal_data()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare result jsonb;
begin
  if auth.uid() is null or lower(coalesce(auth.jwt()->>'email','')) <> 'shekmohammedirfan412@gmail.com' then
    raise exception 'Administrator access required.' using errcode = '42501';
  end if;

  select jsonb_build_object(
    'users', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',u.id,
        'email',u.email,
        'username',p.username,
        'created_at',u.created_at,
        'last_sign_in_at',u.last_sign_in_at,
        'email_confirmed_at',u.email_confirmed_at
      ) order by u.created_at desc)
      from auth.users u left join public.profiles p on p.id=u.id
    ), '[]'::jsonb),
    'private_notes', coalesce((
      select jsonb_agg(jsonb_build_object(
        'user_id',n.user_id,
        'email',u.email,
        'content',n.content,
        'updated_at',n.updated_at
      ) order by n.updated_at desc)
      from public.user_notes n join auth.users u on u.id=n.user_id
    ), '[]'::jsonb),
    'messages', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',m.id,
        'sender_email',m.sender_email,
        'recipient_email',m.recipient_email,
        'body',m.body,
        'created_at',m.created_at
      ) order by m.created_at desc)
      from public.user_messages m
    ), '[]'::jsonb)
  ) into result;
  return result;
end;
$$;
revoke all on function public.admin_get_portal_data() from public, anon;
grant execute on function public.admin_get_portal_data() to authenticated;

-- Ensure only the administrator can edit the announcement even if older permissive
-- policies were added earlier. Remove known legacy write policies before creating ours.
drop policy if exists "Members can edit announcement" on public.admin_announcements;
drop policy if exists "Members can create announcement" on public.admin_announcements;

-- Enable Realtime for the shared announcement so signed-in dashboards can refresh it.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime' and schemaname='public' and tablename='admin_announcements'
  ) then
    alter publication supabase_realtime add table public.admin_announcements;
  end if;
end $$;

notify pgrst, 'reload schema';
