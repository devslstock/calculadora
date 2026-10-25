-- Plantão • Protocolos — esquema multiusuário (Supabase)
-- Rode UMA vez no SQL Editor de um projeto Supabase NOVO e dedicado a este sistema.
-- O primeiro usuário que criar conta vira administrador e já entra ativo; os demais
-- ficam "pendentes" até um administrador ativá-los na aba Equipe.

-- ---------------------------------------------------------------- perfis
create table if not exists public.perfis (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  nome text not null default '',
  ativo boolean not null default false,
  admin boolean not null default false,
  criado_em timestamptz not null default now()
);
alter table public.perfis enable row level security;

create or replace function public.plantao_ativo() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.perfis where id = auth.uid() and ativo)
$$;

create or replace function public.plantao_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.perfis where id = auth.uid() and ativo and admin)
$$;

revoke all on function public.plantao_ativo() from public, anon;
revoke all on function public.plantao_admin() from public, anon;
grant execute on function public.plantao_ativo() to authenticated;
grant execute on function public.plantao_admin() to authenticated;

-- Novo usuário => perfil. O primeiro de todos vira admin ativo; os outros ficam pendentes.
create or replace function public.plantao_novo_usuario() returns trigger
language plpgsql security definer set search_path = public as $$
declare primeiro boolean;
begin
  primeiro := not exists (select 1 from public.perfis);
  insert into public.perfis (id, email, nome, ativo, admin)
  values (new.id, new.email,
          coalesce(nullif(new.raw_user_meta_data->>'nome', ''), split_part(new.email, '@', 1)),
          primeiro, primeiro)
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists plantao_on_auth_user_created on auth.users;
create trigger plantao_on_auth_user_created after insert on auth.users
  for each row execute function public.plantao_novo_usuario();

-- Só admin altera ativo/admin (ninguém se promove sozinho).
create or replace function public.plantao_proteger_perfil() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if (new.ativo is distinct from old.ativo or new.admin is distinct from old.admin)
     and not public.plantao_admin() then
    raise exception 'apenas administradores alteram acesso';
  end if;
  return new;
end $$;

drop trigger if exists plantao_proteger_perfil on public.perfis;
create trigger plantao_proteger_perfil before update on public.perfis
  for each row execute function public.plantao_proteger_perfil();

drop policy if exists perfis_ler on public.perfis;
create policy perfis_ler on public.perfis for select to authenticated
  using (id = auth.uid() or public.plantao_ativo());
drop policy if exists perfis_atualizar on public.perfis;
create policy perfis_atualizar on public.perfis for update to authenticated
  using (id = auth.uid() or public.plantao_admin())
  with check (id = auth.uid() or public.plantao_admin());

revoke all on public.perfis from anon, authenticated;
grant select on public.perfis to authenticated;
grant update (nome, ativo, admin) on public.perfis to authenticated;

-- ------------------------------------------------------------ protocolos
-- Um protocolo por linha. "data" guarda o objeto inteiro; as colunas abaixo são derivadas.
create table if not exists public.protocolos (
  id text primary key,
  data jsonb not null default '{}'::jsonb,
  numero text generated always as (data->>'numero') stored,
  status text generated always as (data->>'status') stored,
  coluna text generated always as (data->>'coluna') stored,
  atualizado_em timestamptz not null default now(),
  atualizado_por uuid default auth.uid(),
  cliente text
);
create unique index if not exists protocolos_numero_uq on public.protocolos (lower(numero));
create index if not exists protocolos_atualizado_idx on public.protocolos (atualizado_em);
alter table public.protocolos enable row level security;

drop policy if exists protocolos_equipe on public.protocolos;
create policy protocolos_equipe on public.protocolos for all to authenticated
  using (public.plantao_ativo()) with check (public.plantao_ativo());

revoke all on public.protocolos from anon;
grant select, insert, update, delete on public.protocolos to authenticated;

-- Mescla só as chaves alteradas: duas pessoas mexendo em campos diferentes do mesmo cartão não se sobrescrevem.
create or replace function public.plantao_patch(p_id text, p_patch jsonb, p_cliente text default null)
returns void language plpgsql security invoker set search_path = public as $$
begin
  insert into public.protocolos (id, data, cliente, atualizado_por)
  values (p_id, p_patch, p_cliente, auth.uid())
  on conflict (id) do update
    set data = public.protocolos.data || excluded.data,
        atualizado_em = now(),
        atualizado_por = auth.uid(),
        cliente = excluded.cliente;
end $$;
revoke all on function public.plantao_patch(text, jsonb, text) from public, anon;
grant execute on function public.plantao_patch(text, jsonb, text) to authenticated;

-- ------------------------------------------------------------- histórico
create table if not exists public.historico (
  id text primary key,
  protocolo_id text,
  numero text,
  acao text,
  detalhe text,
  em timestamptz not null default now(),
  usuario text
);
create index if not exists historico_em_idx on public.historico (em desc);
alter table public.historico enable row level security;

drop policy if exists historico_ler on public.historico;
create policy historico_ler on public.historico for select to authenticated using (public.plantao_ativo());
drop policy if exists historico_inserir on public.historico;
create policy historico_inserir on public.historico for insert to authenticated with check (public.plantao_ativo());

revoke all on public.historico from anon;
grant select, insert on public.historico to authenticated;

-- ------------------------------------------------- configurações (prestadores)
create table if not exists public.kv (
  chave text primary key,
  valor jsonb not null,
  atualizado_em timestamptz not null default now()
);
alter table public.kv enable row level security;

drop policy if exists kv_equipe on public.kv;
create policy kv_equipe on public.kv for all to authenticated
  using (public.plantao_ativo()) with check (public.plantao_ativo());

revoke all on public.kv from anon;
grant select, insert, update, delete on public.kv to authenticated;

-- ---------------------------------------------------------------- anexos
insert into storage.buckets (id, name, public, file_size_limit)
values ('anexos', 'anexos', false, 12582912)
on conflict (id) do nothing;

drop policy if exists anexos_equipe on storage.objects;
create policy anexos_equipe on storage.objects for all to authenticated
  using (bucket_id = 'anexos' and public.plantao_ativo())
  with check (bucket_id = 'anexos' and public.plantao_ativo());

-- ------------------------------------------------------------ tempo real
do $$ begin
  begin alter publication supabase_realtime add table public.protocolos; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.historico; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.kv; exception when duplicate_object then null; end;
end $$;

-- Funções de gatilho não devem ser chamáveis pela API.
revoke all on function public.plantao_novo_usuario() from public, anon, authenticated;
revoke all on function public.plantao_proteger_perfil() from public, anon, authenticated;
