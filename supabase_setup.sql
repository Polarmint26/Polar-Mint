-- =====================================================================
--  POLAR MINT · GESTIONALE  ·  Configurazione database Supabase
--  Da eseguire UNA VOLTA in: Supabase › SQL Editor › New query › Run
--  Si può rieseguire senza problemi (non cancella i dati).
-- =====================================================================

-- 1. TABELLE ------------------------------------------------------------

-- Utenti abilitati, ruolo e reparto
--   role  : admin  = amministratore (titolari): tutto + gestione utenti
--           utente = vede/modifica solo le sezioni permesse dal reparto
--   dept  : magazzino | ordini | amministrazione | lettura | personalizzato
--   perms : per ogni sezione 0 = nascosta, 1 = vede, 2 = modifica
create table if not exists public.app_users (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  email      text,
  role       text not null default 'utente',
  created_at timestamptz not null default now()
);
alter table public.app_users add column if not exists dept  text  not null default 'lettura';
alter table public.app_users add column if not exists perms jsonb not null default '{}'::jsonb;
alter table public.app_users drop constraint if exists app_users_role_check;
-- utenti creati con la versione precedente
update public.app_users
   set dept = 'ordini',
       perms = jsonb_build_object('orders',2,'stock',1,'loads',1,'purch',2,'ddt',2,'clients',2,'listini',2,
               'products',2,'materials',2,'suppliers',2,'haulers',2,'analisi',1,
               'company', case when role = 'editor' then 2 else 0 end,'backup',0)
 where role in ('editor','operatore');
update public.app_users set role = 'utente' where role not in ('admin','utente');
alter table public.app_users alter column role set default 'utente';
alter table public.app_users add constraint app_users_role_check check (role in ('admin','utente'));

-- Dati del gestionale (clienti, prodotti, ordini, magazzino, ...)
create table if not exists public.app_state (
  id         text primary key,
  data       jsonb not null,
  version    bigint not null default 1,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id)
);

-- Storico: copia delle ultime 200 versioni salvate (per recuperare errori)
create table if not exists public.app_state_history (
  id        bigserial primary key,
  state_id  text not null,
  version   bigint not null,
  data      jsonb not null,
  saved_at  timestamptz not null default now(),
  saved_by  uuid
);

alter table public.app_users         enable row level security;
alter table public.app_state         enable row level security;
alter table public.app_state_history enable row level security;

-- 2. RUOLO DELL'UTENTE COLLEGATO ---------------------------------------
create or replace function public.my_role()
returns text language sql stable security definer set search_path = public as $$
  select role from public.app_users where user_id = auth.uid()
$$;

-- 3. OGNI NUOVO UTENTE CREATO IN "Authentication" VIENE ABILITATO -----
--    Il primo utente in assoluto diventa amministratore, gli altri «Sola lettura».
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.app_users(user_id, email, role)
  values (new.id, new.email,
          case when not exists (select 1 from public.app_users where role = 'admin')
               then 'admin' else 'utente' end)
  on conflict (user_id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Utenti già creati prima di questo script (il più vecchio diventa admin)
insert into public.app_users(user_id, email, role)
select u.id, u.email,
       case when row_number() over (order by u.created_at) = 1
                 and not exists (select 1 from public.app_users where role = 'admin')
            then 'admin' else 'utente' end
from auth.users u
order by u.created_at
on conflict (user_id) do nothing;

-- Non si può togliere il ruolo all'ultimo amministratore
create or replace function public.keep_one_admin()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if old.role = 'admin' and new.role <> 'admin'
     and (select count(*) from public.app_users where role = 'admin') <= 1 then
    raise exception 'last_admin';
  end if;
  return new;
end $$;

drop trigger if exists trg_keep_one_admin on public.app_users;
create trigger trg_keep_one_admin
  before update on public.app_users
  for each row execute function public.keep_one_admin();

-- 4. REGOLE DI ACCESSO (RLS) ------------------------------------------
drop policy if exists "users_read"   on public.app_users;
drop policy if exists "users_update" on public.app_users;
create policy "users_read" on public.app_users
  for select to authenticated
  using (user_id = auth.uid() or public.my_role() = 'admin');
create policy "users_update" on public.app_users
  for update to authenticated
  using (public.my_role() = 'admin')
  with check (public.my_role() = 'admin');

drop policy if exists "state_read" on public.app_state;
create policy "state_read" on public.app_state
  for select to authenticated
  using (public.my_role() is not null);

-- Nessuno scrive direttamente: si salva solo tramite save_state()
revoke all on public.app_users         from anon, authenticated;
revoke all on public.app_state         from anon, authenticated;
revoke all on public.app_state_history from anon, authenticated;
grant select on public.app_users to authenticated;
grant update (role, dept, perms) on public.app_users to authenticated;
grant select on public.app_state to authenticated;

-- 5. CONTROLLO PERMESSI PER SEZIONE -----------------------------------
create or replace function public.pm_can(p jsonb, variadic secs text[])
returns boolean language sql immutable as $$
  select exists (select 1 from unnest(secs) s
                 where coalesce(nullif(p->>s,''),'0') ~ '^[0-9]+$'
                   and (p->>s)::int >= 2)
$$;
create or replace function public.pm_cli(d jsonb)
returns jsonb language sql immutable as $$
  select coalesce(jsonb_agg(e - 'prices' order by i), '[]'::jsonb)
  from jsonb_array_elements(coalesce(d->'clients','[]'::jsonb)) with ordinality t(e,i)
$$;
create or replace function public.pm_prices(d jsonb)
returns jsonb language sql immutable as $$
  select coalesce(jsonb_object_agg(coalesce(e->>'id','#'||i), e->'prices'), '{}'::jsonb)
  from jsonb_array_elements(coalesce(d->'clients','[]'::jsonb)) with ordinality t(e,i)
  where jsonb_typeof(e->'prices') = 'object' and e->'prices' <> '{}'::jsonb
$$;
create or replace function public.pm_violation(a jsonb, b jsonb, p jsonb)
returns text language plpgsql immutable as $$
begin
  p := coalesce(p,'{}'::jsonb);
  if pm_cli(a) is distinct from pm_cli(b) and not pm_can(p,'clients') then return 'clients'; end if;
  if pm_prices(a) is distinct from pm_prices(b) and not pm_can(p,'listini','products') then return 'listini'; end if;
  if a->'products'  is distinct from b->'products'  and not pm_can(p,'products') then return 'products'; end if;
  if a->'materials' is distinct from b->'materials' and not pm_can(p,'materials','loads','ddt','orders') then return 'materials'; end if;
  if a->'orders'    is distinct from b->'orders'    and not pm_can(p,'orders','ddt') then return 'orders'; end if;
  if a->'loads'     is distinct from b->'loads'     and not pm_can(p,'loads','purch') then return 'loads'; end if;
  if a->'suppliers' is distinct from b->'suppliers' and not pm_can(p,'suppliers','purch','loads') then return 'suppliers'; end if;
  if a->'haulers'   is distinct from b->'haulers'   and not pm_can(p,'haulers','orders','ddt') then return 'haulers'; end if;
  if a#>'{settings,company}' is distinct from b#>'{settings,company}' and not pm_can(p,'company') then return 'company'; end if;
  if a#>'{settings,pos}' is distinct from b#>'{settings,pos}' and not pm_can(p,'purch','loads') then return 'purch'; end if;
  if (coalesce(a->'settings','{}'::jsonb) - 'company' - 'pos' - 'lastBackup')
     is distinct from (coalesce(b->'settings','{}'::jsonb) - 'company' - 'pos' - 'lastBackup')
     and not exists (select 1 from jsonb_each_text(p) where value ~ '^[0-9]+$' and value::int >= 2)
     then return 'settings'; end if;
  return null;
end $$;

-- 6. SALVATAGGIO SICURO -------------------------------------------------
--  · controlla che l'utente sia abilitato
--  · blocca il salvataggio se un collega ha salvato nel frattempo (conflict)
--  · ogni utente può modificare solo le sezioni permesse dal suo reparto
--  · conserva le ultime 200 versioni nello storico
create or replace function public.save_state(p_data jsonb, p_version bigint)
returns bigint language plpgsql security definer set search_path = public as $$
declare
  r   text;
  pp  jsonb;
  cur public.app_state%rowtype;
  nv  bigint;
  bad text;
begin
  select role, perms into r, pp from public.app_users where user_id = auth.uid();
  if r is null then raise exception 'not_member'; end if;

  select * into cur from public.app_state where id = 'main' for update;

  if not found then
    if r <> 'admin' then raise exception 'only_admin_can_init'; end if;
    insert into public.app_state(id, data, version, updated_by)
    values ('main', p_data, 1, auth.uid());
    return 1;
  end if;

  if cur.version <> p_version then raise exception 'conflict'; end if;

  if r <> 'admin' then
    bad := public.pm_violation(cur.data, p_data, pp);
    if bad is not null then raise exception 'perm_forbidden:%', bad; end if;
  end if;

  insert into public.app_state_history(state_id, version, data, saved_by)
  values ('main', cur.version, cur.data, cur.updated_by);

  delete from public.app_state_history
  where state_id = 'main'
    and id not in (select id from public.app_state_history
                   where state_id = 'main' order by id desc limit 200);

  nv := cur.version + 1;
  update public.app_state
     set data = p_data, version = nv, updated_at = now(), updated_by = auth.uid()
   where id = 'main';
  return nv;
end $$;

revoke all on function public.save_state(jsonb, bigint) from public, anon;
grant execute on function public.save_state(jsonb, bigint) to authenticated;
revoke all on function public.my_role() from public, anon;
grant execute on function public.my_role() to authenticated;

-- Fine. Controllo: deve mostrare gli utenti con il loro ruolo.
select email, role, dept from public.app_users order by created_at;
