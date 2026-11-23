
-- ============================================================
-- ISRLATA MEDIA — THE 200 CREATOR NETWORK
-- FILE: schema.sql
--
-- RUN THIS IN:
-- Supabase Dashboard -> SQL Editor -> New Query
--
-- IMPORTANT:
-- Use a NEW, empty ISRLATA MEDIA database.
-- This script creates the tables, authentication profile trigger,
-- staff access functions, indexes and Row Level Security policies.
--
-- Never put a Supabase secret/service_role key in GitHub.
-- ============================================================

begin;

-- 1. PROFILES
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  creator_name text,
  email text,
  phone text,
  bio text,
  country text default 'Kenya',
  county text,
  role text not null default 'member'
    check (role in ('founder', 'admin', 'member')),
  account_status text not null default 'pending'
    check (account_status in ('pending', 'active', 'suspended')),
  membership_number text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 2. STAFF ACCESS FUNCTIONS
-- SECURITY DEFINER allows these functions to check profiles
-- without causing recursive RLS policy evaluation.

create or replace function public.is_media_staff()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles
    where id = auth.uid()
      and role in ('founder', 'admin')
      and account_status = 'active'
  );
$$;

create or replace function public.is_active_media_member()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles
    where id = auth.uid()
      and role = 'member'
      and account_status = 'active'
  );
$$;

-- 3. AUTOMATIC PROFILE CREATION
-- Every new Supabase Auth user receives a pending member profile.

create or replace function public.handle_new_media_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (
    id,
    full_name,
    creator_name,
    email,
    role,
    account_status
  )
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    coalesce(new.raw_user_meta_data->>'creator_name', ''),
    new.email,
    'member',
    'pending'
  )
  on conflict (id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_media_auth_user_created on auth.users;

create trigger on_media_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_media_user();

-- 4. PROTECT PRIVILEGED PROFILE FIELDS
-- Members cannot promote themselves or activate their own accounts.
-- Founder/admin changes are allowed through trusted management access.

create or replace function public.protect_media_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is not null
     and not public.is_media_staff() then

    if new.role is distinct from old.role
       or new.account_status is distinct from old.account_status
       or new.membership_number is distinct from old.membership_number then
      raise exception 'You are not authorised to change management or membership privileges.';
    end if;
  end if;

  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists protect_media_profile_fields on public.profiles;

create trigger protect_media_profile_fields
before update on public.profiles
for each row execute procedure public.protect_media_profile();

-- 5. CONTENT SUBMISSIONS

create table if not exists public.content_submissions (
  id uuid primary key default gen_random_uuid(),
  creator_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  description text,
  category text not null default 'other',
  platform text not null
    check (platform in ('YouTube', 'TikTok', 'Facebook', 'Instagram', 'Other')),
  video_url text,
  thumbnail_url text,
  editorial_status text not null default 'pending'
    check (editorial_status in ('pending', 'approved', 'revision_required', 'rejected')),
  reviewer_id uuid references public.profiles(id) on delete set null,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists content_creator_idx
on public.content_submissions(creator_id);

create index if not exists content_status_idx
on public.content_submissions(editorial_status);

-- Members may edit their own pending submissions, but cannot
-- alter editorial decisions or reviewer information.

create or replace function public.protect_member_content_review()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is not null
     and not public.is_media_staff() then

    if new.editorial_status is distinct from old.editorial_status
       or new.reviewer_id is distinct from old.reviewer_id
       or new.notes is distinct from old.notes
       or new.creator_id is distinct from old.creator_id then
      raise exception 'Only authorised management can change editorial review information.';
    end if;
  end if;

  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists protect_member_content_review_fields
on public.content_submissions;

create trigger protect_member_content_review_fields
before update on public.content_submissions
for each row execute procedure public.protect_member_content_review();

-- 6. ACCOUNT PERMISSIONS
-- These are written permissions for authorised management activities.
-- Do not store platform passwords or verification codes here.

create table if not exists public.account_permissions (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references public.profiles(id) on delete cascade,
  platform text not null
    check (platform in ('YouTube', 'TikTok', 'Facebook', 'Instagram', 'Other')),
  account_url text not null,
  authorised_actions text[] not null default '{}',
  permission_status text not null default 'pending'
    check (permission_status in ('pending', 'granted', 'revoked', 'expired')),
  authorised_by uuid references public.profiles(id) on delete set null,
  permission_start date,
  permission_end date,
  created_at timestamptz not null default now()
);

create index if not exists account_permissions_member_idx
on public.account_permissions(member_id);

-- 7. DISTRIBUTION CAMPAIGNS

create table if not exists public.distribution_campaigns (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text,
  platform text,
  campaign_status text not null default 'draft'
    check (campaign_status in ('draft', 'active', 'completed', 'cancelled')),
  start_date date,
  end_date date,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);

-- 8. CAMPAIGN PARTICIPATION

create table if not exists public.campaign_shares (
  id uuid primary key default gen_random_uuid(),
  campaign_id uuid not null
    references public.distribution_campaigns(id) on delete cascade,
  member_id uuid not null
    references public.profiles(id) on delete cascade,
  participation_status text not null default 'invited'
    check (participation_status in ('invited', 'accepted', 'declined', 'completed')),
  shared_url text,
  created_at timestamptz not null default now(),
  unique(campaign_id, member_id)
);

-- 9. AUDIT LOGS

create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references public.profiles(id) on delete set null,
  action text not null,
  target_table text,
  target_id uuid,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- 10. INDEXES

create index if not exists profiles_role_idx
on public.profiles(role);

create index if not exists profiles_status_idx
on public.profiles(account_status);

create index if not exists campaigns_status_idx
on public.distribution_campaigns(campaign_status);

create index if not exists campaign_shares_member_idx
on public.campaign_shares(member_id);

-- 11. ENABLE ROW LEVEL SECURITY

alter table public.profiles enable row level security;
alter table public.content_submissions enable row level security;
alter table public.account_permissions enable row level security;
alter table public.distribution_campaigns enable row level security;
alter table public.campaign_shares enable row level security;
alter table public.audit_logs enable row level security;

-- 12. REMOVE EXISTING POLICIES BEFORE RECREATING
-- This makes the policy section safe to rerun.

drop policy if exists "profiles_read_own_or_staff" on public.profiles;
drop policy if exists "profiles_update_own_or_staff" on public.profiles;
drop policy if exists "profiles_staff_insert" on public.profiles;
drop policy if exists "profiles_staff_delete" on public.profiles;

drop policy if exists "content_read_own_or_staff" on public.content_submissions;
drop policy if exists "content_insert_active_member" on public.content_submissions;
drop policy if exists "content_update_own_pending_or_staff" on public.content_submissions;
drop policy if exists "content_staff_delete" on public.content_submissions;

drop policy if exists "permissions_read_own_or_staff" on public.account_permissions;
drop policy if exists "permissions_member_request" on public.account_permissions;
drop policy if exists "permissions_member_revoke" on public.account_permissions;
drop policy if exists "permissions_staff_manage" on public.account_permissions;

drop policy if exists "campaigns_read_active_or_staff" on public.distribution_campaigns;
drop policy if exists "campaigns_staff_manage" on public.distribution_campaigns;

drop policy if exists "shares_read_own_or_staff" on public.campaign_shares;
drop policy if exists "shares_member_join" on public.campaign_shares;
drop policy if exists "shares_member_update_own" on public.campaign_shares;
drop policy if exists "shares_staff_manage" on public.campaign_shares;

drop policy if exists "audit_staff_read" on public.audit_logs;
drop policy if exists "audit_staff_insert" on public.audit_logs;

-- 13. PROFILE POLICIES

create policy "profiles_read_own_or_staff"
on public.profiles for select
to authenticated
using (id = auth.uid() or public.is_media_staff());

create policy "profiles_update_own_or_staff"
on public.profiles for update
to authenticated
using (id = auth.uid() or public.is_media_staff())
with check (id = auth.uid() or public.is_media_staff());

create policy "profiles_staff_insert"
on public.profiles for insert
to authenticated
with check (public.is_media_staff());

create policy "profiles_staff_delete"
on public.profiles for delete
to authenticated
using (public.is_media_staff());

-- 14. CONTENT POLICIES

create policy "content_read_own_or_staff"
on public.content_submissions for select
to authenticated
using (creator_id = auth.uid() or public.is_media_staff());

create policy "content_insert_active_member"
on public.content_submissions for insert
to authenticated
with check (
  creator_id = auth.uid()
  and public.is_active_media_member()
);

create policy "content_update_own_pending_or_staff"
on public.content_submissions for update
to authenticated
using (
  public.is_media_staff()
  or (
    creator_id = auth.uid()
    and editorial_status in ('pending', 'revision_required')
  )
)
with check (
  public.is_media_staff()
  or (
    creator_id = auth.uid()
    and editorial_status in ('pending', 'revision_required')
  )
);

create policy "content_staff_delete"
on public.content_submissions for delete
to authenticated
using (public.is_media_staff());

-- 15. ACCOUNT PERMISSION POLICIES

create policy "permissions_read_own_or_staff"
on public.account_permissions for select
to authenticated
using (member_id = auth.uid() or public.is_media_staff());

create policy "permissions_member_request"
on public.account_permissions for insert
to authenticated
with check (
  member_id = auth.uid()
  and public.is_active_media_member()
  and permission_status = 'pending'
);

create policy "permissions_member_revoke"
on public.account_permissions for update
to authenticated
using (member_id = auth.uid() or public.is_media_staff())
with check (member_id = auth.uid() or public.is_media_staff());

create policy "permissions_staff_manage"
on public.account_permissions for all
to authenticated
using (public.is_media_staff())
with check (public.is_media_staff());

-- 16. CAMPAIGN POLICIES

create policy "campaigns_read_active_or_staff"
on public.distribution_campaigns for select
to authenticated
using (
  public.is_media_staff()
  or (
    public.is_active_media_member()
    and campaign_status = 'active'
  )
);

create policy "campaigns_staff_manage"
on public.distribution_campaigns for all
to authenticated
using (public.is_media_staff())
with check (public.is_media_staff());

-- 17. CAMPAIGN PARTICIPATION POLICIES

create policy "shares_read_own_or_staff"
on public.campaign_shares for select
to authenticated
using (member_id = auth.uid() or public.is_media_staff());

create policy "shares_member_join"
on public.campaign_shares for insert
to authenticated
with check (
  member_id = auth.uid()
  and public.is_active_media_member()
);

create policy "shares_member_update_own"
on public.campaign_shares for update
to authenticated
using (member_id = auth.uid() or public.is_media_staff())
with check (member_id = auth.uid() or public.is_media_staff());

create policy "shares_staff_manage"
on public.campaign_shares for all
to authenticated
using (public.is_media_staff())
with check (public.is_media_staff());

-- 18. AUDIT LOG POLICIES

create policy "audit_staff_read"
on public.audit_logs for select
to authenticated
using (public.is_media_staff());

create policy "audit_staff_insert"
on public.audit_logs for insert
to authenticated
with check (public.is_media_staff());

-- 19. TABLE PRIVILEGES
-- RLS still controls which records each authenticated user can access.

grant usage on schema public to authenticated;

grant select, insert, update, delete
on public.profiles,
   public.content_submissions,
   public.account_permissions,
   public.distribution_campaigns,
   public.campaign_shares,
   public.audit_logs
to authenticated;

-- Allow the database functions to be called by authenticated sessions.
grant execute on function public.is_media_staff() to authenticated;
grant execute on function public.is_active_media_member() to authenticated;

commit;

-- 20. SETUP VERIFICATION

select
  'ISRLATA MEDIA database foundation installed' as setup_status,
  now() as installed_at;

select
  table_name
from information_schema.tables
where table_schema = 'public'
  and table_name in (
    'profiles',
    'content_submissions',
    'account_permissions',
    'distribution_campaigns',
    'campaign_shares',
    'audit_logs'
  )
order by table_name;
