-- Inventory schema for Supabase/PostgreSQL
-- Multi-tenant model: every product/category belongs to one business.
-- RLS guarantees authenticated users can only access rows for their own business.

create extension if not exists pgcrypto;

create schema if not exists private;

create type public.profile_role as enum ('owner', 'admin', 'staff');
create type public.product_status as enum ('available', 'low_stock', 'critical', 'archived');

create table public.businesses (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  business_id uuid not null references public.businesses(id) on delete restrict,
  full_name text,
  role public.profile_role not null default 'staff',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, business_id)
);

create table public.categories (
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses(id) on delete cascade,
  name text not null,
  description text,
  color text,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, business_id),
  unique (business_id, name)
);

create table public.products (
  id uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses(id) on delete cascade,
  category_id uuid,
  sku text not null,
  name text not null,
  description text,
  stock integer not null default 0 check (stock >= 0),
  min_stock integer not null default 0 check (min_stock >= 0),
  unit_price numeric(12, 2) not null default 0 check (unit_price >= 0),
  status public.product_status not null default 'available',
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (business_id, sku),
  constraint products_category_same_business
    foreign key (category_id, business_id)
    references public.categories(id, business_id)
    on update cascade
);

create index profiles_business_id_idx on public.profiles (business_id);
create index categories_business_id_idx on public.categories (business_id);
create index products_business_id_idx on public.products (business_id);
create index products_category_id_idx on public.products (category_id);
create index products_status_idx on public.products (business_id, status);
create index products_search_idx on public.products using gin (
  to_tsvector('simple', coalesce(name, '') || ' ' || coalesce(sku, '') || ' ' || coalesce(description, ''))
);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger set_businesses_updated_at
before update on public.businesses
for each row execute function public.set_updated_at();

create trigger set_profiles_updated_at
before update on public.profiles
for each row execute function public.set_updated_at();

create trigger set_categories_updated_at
before update on public.categories
for each row execute function public.set_updated_at();

create trigger set_products_updated_at
before update on public.products
for each row execute function public.set_updated_at();

-- Private authorization helpers.
-- They live outside the exposed public schema to avoid direct API access.
create or replace function private.user_business_id(user_id uuid)
returns uuid
language sql
security definer
set search_path = public
stable
as $$
  select p.business_id
  from public.profiles p
  where p.id = user_id
  limit 1
$$;

create or replace function private.user_role_for_business(user_id uuid, target_business_id uuid)
returns public.profile_role
language sql
security definer
set search_path = public
stable
as $$
  select p.role
  from public.profiles p
  where p.id = user_id
    and p.business_id = target_business_id
  limit 1
$$;

create or replace function private.is_business_member(target_business_id uuid)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = (select auth.uid())
      and p.business_id = target_business_id
  )
$$;

create or replace function private.is_business_admin(target_business_id uuid)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = (select auth.uid())
      and p.business_id = target_business_id
      and p.role in ('owner', 'admin')
  )
$$;

revoke all on schema private from public;
grant usage on schema private to authenticated;
grant execute on all functions in schema private to authenticated;

alter table public.businesses enable row level security;
alter table public.profiles enable row level security;
alter table public.categories enable row level security;
alter table public.products enable row level security;

-- Businesses
create policy "members can read their business"
on public.businesses
for select
to authenticated
using (
  owner_id = (select auth.uid())
  or private.is_business_member(id)
);

create policy "users can create owned businesses"
on public.businesses
for insert
to authenticated
with check (
  (select auth.uid()) is not null
  and owner_id = (select auth.uid())
);

create policy "owners can update their business"
on public.businesses
for update
to authenticated
using (private.user_role_for_business((select auth.uid()), id) = 'owner')
with check (private.user_role_for_business((select auth.uid()), id) = 'owner');

-- Profiles
create policy "members can read profiles in their business"
on public.profiles
for select
to authenticated
using (
  business_id = private.user_business_id((select auth.uid()))
);

create policy "users can create their owner profile"
on public.profiles
for insert
to authenticated
with check (
  id = (select auth.uid())
  and role = 'owner'
  and exists (
    select 1
    from public.businesses b
    where b.id = profiles.business_id
      and b.owner_id = (select auth.uid())
  )
);

create policy "users can update their own profile without switching business"
on public.profiles
for update
to authenticated
using (id = (select auth.uid()))
with check (
  id = (select auth.uid())
  and business_id = private.user_business_id((select auth.uid()))
);

-- Categories
create policy "members can read categories"
on public.categories
for select
to authenticated
using (private.is_business_member(business_id));

create policy "members can create categories"
on public.categories
for insert
to authenticated
with check (private.is_business_member(business_id));

create policy "members can update categories"
on public.categories
for update
to authenticated
using (private.is_business_member(business_id))
with check (private.is_business_member(business_id));

create policy "admins can delete categories"
on public.categories
for delete
to authenticated
using (private.is_business_admin(business_id));

-- Products
create policy "members can read products"
on public.products
for select
to authenticated
using (private.is_business_member(business_id));

create policy "members can create products"
on public.products
for insert
to authenticated
with check (
  private.is_business_member(business_id)
  and (
    category_id is null
    or exists (
      select 1
      from public.categories c
      where c.id = products.category_id
        and c.business_id = products.business_id
    )
  )
);

create policy "members can update products"
on public.products
for update
to authenticated
using (private.is_business_member(business_id))
with check (
  private.is_business_member(business_id)
  and (
    category_id is null
    or exists (
      select 1
      from public.categories c
      where c.id = products.category_id
        and c.business_id = products.business_id
    )
  )
);

create policy "admins can delete products"
on public.products
for delete
to authenticated
using (private.is_business_admin(business_id));

grant usage on schema public to anon, authenticated;
grant select, insert, update on public.businesses to authenticated;
grant select, insert, update on public.profiles to authenticated;
grant select, insert, update, delete on public.categories to authenticated;
grant select, insert, update, delete on public.products to authenticated;
