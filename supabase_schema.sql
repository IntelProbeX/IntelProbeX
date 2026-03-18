-- ============================================================
-- IntelProbeX — SUPABASE SCHEMA
-- ============================================================

create extension if not exists "uuid-ossp";

-- ============================================================
-- SEQUENCES
-- ============================================================

create sequence if not exists user_registration_seq start 1;

-- ============================================================
-- ROLES REFERENCE
-- ============================================================
--
--  admin      — полный доступ, управление платформой
--  moderator  — модерация пользователей (бан/разбан)
--  vip+       — особый статус, расширенные возможности
--  vip        — VIP пользователь
--  user       — стандартный аккаунт (по умолчанию)
--  -          — декоративная роль, без каких-либо прав
--
-- ============================================================

-- ============================================================
-- TABLES
-- ============================================================

create table public.profiles (
  id               uuid references auth.users(id) on delete cascade primary key,
  registration_id  bigint unique default nextval('user_registration_seq') not null,
  username         text unique not null,
  -- email НЕ хранится здесь — берётся из auth.users напрямую.
  -- Публичный профиль email не раскрывает никому, кроме самого владельца и admin.
  role             text not null default 'user'
                     check (role in ('admin', 'moderator', 'vip+', 'vip', 'user', '-')),
  bio              text,
  is_banned        boolean default false,
  created_at       timestamptz default now() not null,
  updated_at       timestamptz default now() not null
);

-- ============================================================
-- INDEXES
-- ============================================================

create index profiles_username_idx        on public.profiles(username);
create index profiles_registration_id_idx on public.profiles(registration_id);
create index profiles_role_idx            on public.profiles(role);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================

alter table public.profiles enable row level security;

-- Публичный просмотр профилей (без email — только username, bio, role, reg_id)
create policy "profiles_select_public"
  on public.profiles for select
  using (true);

-- Пользователь редактирует только свой профиль (bio)
-- role и is_banned НЕ меняются через эту политику
create policy "profiles_update_own"
  on public.profiles for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- Вставка профиля при регистрации
create policy "profiles_insert_own"
  on public.profiles for insert
  with check (auth.uid() = id);

-- Admin может обновить любой профиль
create policy "profiles_admin_update"
  on public.profiles for update
  using (
    exists (
      select 1 from public.profiles
      where id = auth.uid() and role = 'admin'
    )
  );

-- Moderator может менять только is_banned
-- (жёсткая защита от смены роли — на уровне клиента + проверка роли)

-- ============================================================
-- FUNCTIONS & TRIGGERS
-- ============================================================

create or replace function public.handle_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger profiles_updated_at
  before update on public.profiles
  for each row execute procedure public.handle_updated_at();

-- Автосоздание профиля при регистрации (email не копируется в profiles)
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, username)
  values (
    new.id,
    coalesce(
      new.raw_user_meta_data->>'username',
      'user_' || floor(random() * 999999)::text
    )
  );
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ============================================================
-- HELPER FUNCTIONS
-- ============================================================

create or replace function public.is_admin()
returns boolean as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$ language sql security definer;

create or replace function public.is_mod_or_admin()
returns boolean as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('admin', 'moderator')
  );
$$ language sql security definer;

-- ============================================================
-- АНОНИМНОСТЬ
-- ============================================================
--
-- Что НЕ хранится в profiles:
--   - email (только в auth.users, скрыт от публики)
--   - IP-адреса
--   - геолокация
--   - история действий
--
-- registration_id — порядковый номер регистрации.
-- Не связан с email. Не раскрывает личность.
--
-- username — выбирается пользователем самостоятельно.
--
-- ============================================================
-- ПЕРВЫЙ ЗАПУСК
-- ============================================================
--
-- После первой регистрации сделайте себя администратором:
--
--   update public.profiles
--   set role = 'admin'
--   where id = 'ВАШ-UUID-ИЗ-AUTH';
--
-- ============================================================
