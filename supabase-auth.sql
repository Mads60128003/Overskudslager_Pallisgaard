-- Run this once in Supabase SQL Editor after enabling Email Auth.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text not null default 'user' check (role in ('admin', 'user')),
  created_at timestamptz not null default now()
);

alter table public.profiles add column if not exists email text;
alter table public.profiles enable row level security;
alter table public.items enable row level security;
alter table public.categories enable row level security;

create or replace function public.current_role()
returns text language sql stable security definer set search_path = public
as $$ select role from public.profiles where id = auth.uid() $$;

create or replace function public.create_profile()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.create_profile();

drop policy if exists "Authenticated users can read items" on public.items;
create policy "Authenticated users can read items" on public.items for select to authenticated using (true);
drop policy if exists "Admins can insert items" on public.items;
create policy "Admins can insert items" on public.items for insert to authenticated with check (public.current_role() = 'admin');
drop policy if exists "Admins can update items" on public.items;
create policy "Admins can update items" on public.items for update to authenticated using (public.current_role() = 'admin') with check (public.current_role() = 'admin');
drop policy if exists "Users can perform stock actions" on public.items;
create policy "Users can perform stock actions" on public.items for update to authenticated using (true) with check (quantity >= 0);
drop policy if exists "Admins can delete items" on public.items;
create policy "Admins can delete items" on public.items for delete to authenticated using (public.current_role() = 'admin');

drop policy if exists "Authenticated users can read categories" on public.categories;
create policy "Authenticated users can read categories" on public.categories for select to authenticated using (true);
drop policy if exists "Admins can manage categories" on public.categories;
create policy "Admins can manage categories" on public.categories for all to authenticated using (public.current_role() = 'admin') with check (public.current_role() = 'admin');

drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile" on public.profiles for select to authenticated using (id = auth.uid());

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

-- After the first account is email-verified, promote it:
-- update public.profiles set role = 'admin' where email = 'admin@firma.dk';
