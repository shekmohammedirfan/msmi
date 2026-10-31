-- MSMI PORTAL V2 MIGRATION
-- Run AFTER the existing base schema (MSMI_schema_with_notepad.sql) and admin upgrade.
-- Uses Supabase Auth + RLS. Never put a service_role key in browser HTML.

-- 1) Advanced member profiles
alter table public.profiles add column if not exists display_name text not null default '';
alter table public.profiles add column if not exists bio text not null default '';
alter table public.profiles add column if not exists status_message text not null default '';
alter table public.profiles add column if not exists avatar_url text;

-- 2) Multiple private notes (keeps the existing single private/public notepads intact)
create table if not exists public.user_notes_v2(
 id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade,
 title text not null default 'Untitled note' check(char_length(title) between 1 and 100),
 content text not null default '', created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index if not exists user_notes_v2_owner_updated_idx on public.user_notes_v2(user_id,updated_at desc);
alter table public.user_notes_v2 enable row level security;
drop policy if exists "MSMI V2 notes own select" on public.user_notes_v2;
create policy "MSMI V2 notes own select" on public.user_notes_v2 for select to authenticated using(user_id=auth.uid());
drop policy if exists "MSMI V2 notes own insert" on public.user_notes_v2;
create policy "MSMI V2 notes own insert" on public.user_notes_v2 for insert to authenticated with check(user_id=auth.uid());
drop policy if exists "MSMI V2 notes own update" on public.user_notes_v2;
create policy "MSMI V2 notes own update" on public.user_notes_v2 for update to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());
drop policy if exists "MSMI V2 notes own delete" on public.user_notes_v2;
create policy "MSMI V2 notes own delete" on public.user_notes_v2 for delete to authenticated using(user_id=auth.uid());
grant select,insert,update,delete on public.user_notes_v2 to authenticated;

-- 3) Notifications
create table if not exists public.portal_notifications(
 id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade,
 title text not null, body text not null default '', kind text not null default 'general',
 created_at timestamptz not null default now(), read_at timestamptz
);
create index if not exists portal_notifications_owner_date_idx on public.portal_notifications(user_id,created_at desc);
alter table public.portal_notifications enable row level security;
drop policy if exists "MSMI V2 notifications read own" on public.portal_notifications;
create policy "MSMI V2 notifications read own" on public.portal_notifications for select to authenticated using(user_id=auth.uid());
drop policy if exists "MSMI V2 notifications update own" on public.portal_notifications;
create policy "MSMI V2 notifications update own" on public.portal_notifications for update to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());
grant select,update on public.portal_notifications to authenticated;

create or replace function public.msmi_notify_private_message() returns trigger language plpgsql security definer set search_path='' as $$
begin
 insert into public.portal_notifications(user_id,title,body,kind) values(new.recipient_id,'New private message','You received a new message from '||coalesce(new.sender_email,'an MSMI member'),'private_message');
 return new;
end; $$;
drop trigger if exists msmi_notify_private_message on public.user_messages;
create trigger msmi_notify_private_message after insert on public.user_messages for each row execute function public.msmi_notify_private_message();
create or replace function public.msmi_notify_announcement() returns trigger language plpgsql security definer set search_path='' as $$
begin
 if new.content is distinct from old.content then
  insert into public.portal_notifications(user_id,title,body,kind)
  select id,'MSMI announcement',left(new.content,500),'announcement' from auth.users where id is distinct from new.updated_by;
 end if;
 return new;
end; $$;
drop trigger if exists msmi_notify_announcement on public.admin_announcements;
create trigger msmi_notify_announcement after update on public.admin_announcements for each row execute function public.msmi_notify_announcement();

-- Add read receipts/edit timestamps to existing direct messages.
alter table public.user_messages add column if not exists is_read boolean not null default false;
alter table public.user_messages add column if not exists edited_at timestamptz;
drop policy if exists "MSMI V2 recipient can mark read" on public.user_messages;
create policy "MSMI V2 recipient can mark read" on public.user_messages for update to authenticated using(recipient_id=auth.uid()) with check(recipient_id=auth.uid());
revoke update on public.user_messages from authenticated;
grant update(is_read) on public.user_messages to authenticated;
create or replace function public.edit_own_portal_message(p_message_id uuid,p_body text) returns void language plpgsql security definer set search_path='' as $$
begin
 if auth.uid() is null then raise exception 'Sign in required.'; end if;
 if p_body is null or char_length(trim(p_body)) not between 1 and 5000 then raise exception 'Message must contain 1 to 5000 characters.'; end if;
 update public.user_messages set body=trim(p_body),edited_at=now() where id=p_message_id and sender_id=auth.uid();
 if not found then raise exception 'Message not found or you are not its sender.'; end if;
end; $$;
revoke all on function public.edit_own_portal_message(uuid,text) from public,anon;
grant execute on function public.edit_own_portal_message(uuid,text) to authenticated;

-- 4) Login activity. Browser sends only its user-agent; the server supplies the user ID.
create table if not exists public.portal_login_activity(
 id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade,
 user_agent text not null default '', created_at timestamptz not null default now()
);
create index if not exists portal_login_activity_owner_date_idx on public.portal_login_activity(user_id,created_at desc);
alter table public.portal_login_activity enable row level security;
drop policy if exists "MSMI V2 login history read own" on public.portal_login_activity;
create policy "MSMI V2 login history read own" on public.portal_login_activity for select to authenticated using(user_id=auth.uid());
grant select on public.portal_login_activity to authenticated;
create or replace function public.record_portal_login(p_user_agent text default '') returns void language plpgsql security definer set search_path='' as $$
begin
 if auth.uid() is null then raise exception 'Sign in required.'; end if;
 insert into public.portal_login_activity(user_id,user_agent) values(auth.uid(),left(coalesce(p_user_agent,''),500));
end; $$;
revoke all on function public.record_portal_login(text) from public,anon;
grant execute on function public.record_portal_login(text) to authenticated;

-- 5) Private groups and group messages
create table if not exists public.chat_groups(
 id uuid primary key default gen_random_uuid(), name text not null check(char_length(name) between 1 and 70),
 created_by uuid not null references auth.users(id) on delete cascade, created_at timestamptz not null default now()
);
create table if not exists public.chat_group_members(
 group_id uuid not null references public.chat_groups(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade, joined_at timestamptz not null default now(),
 primary key(group_id,user_id)
);
create table if not exists public.group_messages(
 id uuid primary key default gen_random_uuid(), group_id uuid not null references public.chat_groups(id) on delete cascade,
 sender_id uuid not null references auth.users(id) on delete cascade, body text not null check(char_length(body) between 1 and 3000),
 created_at timestamptz not null default now()
);
create index if not exists group_messages_group_date_idx on public.group_messages(group_id,created_at);
alter table public.chat_groups enable row level security;
alter table public.chat_group_members enable row level security;
alter table public.group_messages enable row level security;
drop policy if exists "MSMI V2 group members read groups" on public.chat_groups;
create policy "MSMI V2 group members read groups" on public.chat_groups for select to authenticated using(exists(select 1 from public.chat_group_members m where m.group_id=chat_groups.id and m.user_id=auth.uid()));
drop policy if exists "MSMI V2 read own group memberships" on public.chat_group_members;
create policy "MSMI V2 read own group memberships" on public.chat_group_members for select to authenticated using(user_id=auth.uid());
drop policy if exists "MSMI V2 read group messages" on public.group_messages;
create policy "MSMI V2 read group messages" on public.group_messages for select to authenticated using(exists(select 1 from public.chat_group_members m where m.group_id=group_messages.group_id and m.user_id=auth.uid()));
drop policy if exists "MSMI V2 send group messages" on public.group_messages;
create policy "MSMI V2 send group messages" on public.group_messages for insert to authenticated with check(sender_id=auth.uid() and exists(select 1 from public.chat_group_members m where m.group_id=group_messages.group_id and m.user_id=auth.uid()));
grant select on public.chat_groups,public.chat_group_members,public.group_messages to authenticated;
grant insert on public.group_messages to authenticated;
create or replace function public.create_portal_group(p_name text) returns jsonb language plpgsql security definer set search_path='' as $$
declare gid uuid;
begin
 if auth.uid() is null then raise exception 'Sign in required.'; end if;
 if p_name is null or char_length(trim(p_name)) not between 1 and 70 then raise exception 'Group name must be 1 to 70 characters.'; end if;
 insert into public.chat_groups(name,created_by) values(trim(p_name),auth.uid()) returning id into gid;
 insert into public.chat_group_members(group_id,user_id) values(gid,auth.uid());
 return jsonb_build_object('group_id',gid);
end; $$;
revoke all on function public.create_portal_group(text) from public,anon;
grant execute on function public.create_portal_group(text) to authenticated;
create or replace function public.invite_portal_group_member(p_group_id uuid,p_email text) returns void language plpgsql security definer set search_path='' as $$
declare target_id uuid; creator_id uuid;
begin
 if auth.uid() is null then raise exception 'Sign in required.'; end if;
 select created_by into creator_id from public.chat_groups where id=p_group_id;
 if creator_id is null or creator_id<>auth.uid() then raise exception 'Only the group creator can invite members.'; end if;
 select id into target_id from auth.users where lower(email)=lower(trim(p_email)) and email_confirmed_at is not null limit 1;
 if target_id is null then raise exception 'No confirmed MSMI account found for this email.'; end if;
 insert into public.chat_group_members(group_id,user_id) values(p_group_id,target_id) on conflict do nothing;
 insert into public.portal_notifications(user_id,title,body,kind) values(target_id,'Added to a group','You were added to an MSMI group.','group_invite');
end; $$;
revoke all on function public.invite_portal_group_member(uuid,text) from public,anon;
grant execute on function public.invite_portal_group_member(uuid,text) to authenticated;
create or replace function public.portal_group_member_count(p_group_id uuid) returns integer language plpgsql security definer set search_path='' as $$
declare n integer;
begin
 if auth.uid() is null or not exists(select 1 from public.chat_group_members where group_id=p_group_id and user_id=auth.uid()) then raise exception 'Group membership required.'; end if;
 select count(*) into n from public.chat_group_members where group_id=p_group_id;
 return n;
end; $$;
revoke all on function public.portal_group_member_count(uuid) from public,anon;
grant execute on function public.portal_group_member_count(uuid) to authenticated;
create or replace function public.msmi_notify_group_message() returns trigger language plpgsql security definer set search_path='' as $$
begin
 insert into public.portal_notifications(user_id,title,body,kind)
 select m.user_id,'New group message','A group member posted a new message.','group_message' from public.chat_group_members m
 where m.group_id=new.group_id and m.user_id<>new.sender_id;
 return new;
end; $$;
drop trigger if exists msmi_notify_group_message on public.group_messages;
create trigger msmi_notify_group_message after insert on public.group_messages for each row execute function public.msmi_notify_group_message();

-- 6) Private Supabase Storage bucket. Each object must be inside the owner's UUID folder.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('msmi-cloud','msmi-cloud',false,20971520,null)
on conflict(id) do update set public=false,file_size_limit=20971520;
drop policy if exists "MSMI V2 users read own cloud files" on storage.objects;
create policy "MSMI V2 users read own cloud files" on storage.objects for select to authenticated using(bucket_id='msmi-cloud' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists "MSMI V2 users upload own cloud files" on storage.objects;
create policy "MSMI V2 users upload own cloud files" on storage.objects for insert to authenticated with check(bucket_id='msmi-cloud' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists "MSMI V2 users update own cloud files" on storage.objects;
create policy "MSMI V2 users update own cloud files" on storage.objects for update to authenticated using(bucket_id='msmi-cloud' and (storage.foldername(name))[1]=auth.uid()::text) with check(bucket_id='msmi-cloud' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists "MSMI V2 users delete own cloud files" on storage.objects;
create policy "MSMI V2 users delete own cloud files" on storage.objects for delete to authenticated using(bucket_id='msmi-cloud' and (storage.foldername(name))[1]=auth.uid()::text);

-- 7) Admin-only analytics summary. Does not return message contents, file contents or passwords.
create or replace function public.admin_portal_analytics() returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb;
begin
 if auth.uid() is null or lower(coalesce(auth.jwt()->>'email',''))<>'shekmohammedirfan412@gmail.com' then raise exception 'Administrator access required.' using errcode='42501'; end if;
 select jsonb_build_object(
  'members',(select count(*) from auth.users),
  'private_notes',(select count(*) from public.user_notes_v2),
  'messages',(select count(*) from public.user_messages),
  'groups',(select count(*) from public.chat_groups),
  'group_messages',(select count(*) from public.group_messages),
  'files',(select count(*) from storage.objects where bucket_id='msmi-cloud')
 ) into result;
 return result;
end; $$;
revoke all on function public.admin_portal_analytics() from public,anon;
grant execute on function public.admin_portal_analytics() to authenticated;

-- Realtime feeds for notifications and group conversations.
do $$ begin
 if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='portal_notifications') then alter publication supabase_realtime add table public.portal_notifications; end if;
 if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='group_messages') then alter publication supabase_realtime add table public.group_messages; end if;
end $$;
notify pgrst,'reload schema';
