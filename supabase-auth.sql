-- Run this once in the Supabase SQL Editor after enabling Email Auth.
-- Existing profiles stay usable; new profiles must be approved by an admin.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text not null default 'user' check (role in ('admin', 'user')),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'inactive')),
  created_at timestamptz not null default now()
);

alter table public.profiles add column if not exists email text;
alter table public.profiles add column if not exists status text;
-- Do not lock out accounts that existed before approval was introduced.
update public.profiles set status = 'approved' where status is null;
alter table public.profiles alter column status set default 'pending';
alter table public.profiles alter column status set not null;
alter table public.profiles drop constraint if exists profiles_status_check;
alter table public.profiles add constraint profiles_status_check
  check (status in ('pending', 'approved', 'rejected', 'inactive'));

alter table public.profiles enable row level security;
alter table public.items enable row level security;
alter table public.categories enable row level security;

create or replace function public.current_role()
returns text language sql stable security definer set search_path = public
as $$ select role from public.profiles where id = auth.uid() $$;

create or replace function public.current_status()
returns text language sql stable security definer set search_path = public
as $$ select status from public.profiles where id = auth.uid() $$;

create or replace function public.can_access_app()
returns boolean language sql stable security definer set search_path = public
as $$ select coalesce(public.current_role() = 'admin' or public.current_status() = 'approved', false) $$;

create or replace function public.create_profile()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, status) values (new.id, new.email, 'pending');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.create_profile();

drop policy if exists "Authenticated users can read items" on public.items;
create policy "Approved users can read items" on public.items for select to authenticated using (public.can_access_app());
drop policy if exists "Admins can insert items" on public.items;
create policy "Admins can insert items" on public.items for insert to authenticated with check (public.current_role() = 'admin');
drop policy if exists "Admins can update items" on public.items;
create policy "Admins can update items" on public.items for update to authenticated using (public.current_role() = 'admin') with check (public.current_role() = 'admin');
drop policy if exists "Users can perform stock actions" on public.items;
create policy "Approved users can perform stock actions" on public.items for update to authenticated using (public.can_access_app()) with check (public.can_access_app() and quantity >= 0);
drop policy if exists "Admins can delete items" on public.items;
create policy "Admins can delete items" on public.items for delete to authenticated using (public.current_role() = 'admin');

drop policy if exists "Authenticated users can read categories" on public.categories;
create policy "Approved users can read categories" on public.categories for select to authenticated using (public.can_access_app());
drop policy if exists "Admins can manage categories" on public.categories;
create policy "Admins can manage categories" on public.categories for all to authenticated using (public.current_role() = 'admin') with check (public.current_role() = 'admin');

drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile" on public.profiles for select to authenticated using (id = auth.uid());
drop policy if exists "Admins can read all profiles" on public.profiles;
create policy "Admins can read all profiles" on public.profiles for select to authenticated using (public.current_role() = 'admin');
drop policy if exists "Admins can update profiles" on public.profiles;
create policy "Admins can update profiles" on public.profiles for update to authenticated
  using (public.current_role() = 'admin') with check (public.current_role() = 'admin');

create or replace function public.validate_profile_role()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  if new.role not in ('admin', 'user') then
    raise exception 'Invalid profile role';
  end if;
  if new.status not in ('pending', 'approved', 'rejected', 'inactive') then
    raise exception 'Invalid profile status';
  end if;
  return new;
end;
$$;

drop trigger if exists validate_profile_role on public.profiles;
create trigger validate_profile_role
  before insert or update on public.profiles
  for each row execute procedure public.validate_profile_role();

create or replace function public.restrict_user_item_updates()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  if public.current_role() <> 'admin' and (
    new.name is distinct from old.name or
    new.category_id is distinct from old.category_id or
    new.photo_path is distinct from old.photo_path
  ) then
    raise exception 'Only administrators can edit item details';
  end if;
  return new;
end;
$$;

drop trigger if exists restrict_user_item_updates on public.items;
create trigger restrict_user_item_updates
  before update on public.items
  for each row execute procedure public.restrict_user_item_updates();

-- After the first account is email-verified, promote it manually:
-- update public.profiles set role = 'admin', status = 'approved' where email = 'admin@firma.dk';
