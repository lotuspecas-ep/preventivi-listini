-- Hardening Copia Commissioni (progetto Supabase "preventivi")
-- Idempotente. Eseguire nel SQL Editor. Non modifica policy RLS né dati.

-- 1) authenticated: via TRUNCATE (aggira la RLS), REFERENCES e TRIGGER
revoke truncate, references, trigger on
public.clienti, public.documenti, public.listino_items,
public.listino_log, public.listino_unita
from authenticated;

-- 2) listino_log: il client la legge soltanto (policy gia' solo SELECT)
revoke insert, update, delete on public.listino_log from authenticated;

-- 3) Funzioni trigger: non devono essere richiamabili dall'API
-- (i trigger continuano a funzionare: l'execute si controlla alla creazione)
revoke execute on function public.guard_locked() from public, anon, authenticated;
revoke execute on function public.listino_touch() from public, anon, authenticated;
revoke execute on function public.unita_touch() from public, anon, authenticated;
revoke execute on function public.clienti_touch() from public, anon, authenticated;

-- 4) MODELLO per ogni tabella nuova creata dal 30/10/2026 (Supabase non concede piu' i grant in automatico)
-- alter table public.NOME enable row level security;
-- grant select, insert, update, delete on public.NOME to authenticated;
-- grant select, insert, update, delete on public.NOME to service_role;
-- anon: SOLO se la tabella e' davvero pubblica. Di norma NO.
-- create policy ... on public.NOME for ... to authenticated using (...) with check (...);

-- Verifica finale
select table_name, grantee, string_agg(privilege_type, ',' order by privilege_type) privs
from information_schema.role_table_grants
where table_schema='public' and grantee in ('anon','authenticated')
group by 1,2 order by 1,2;
