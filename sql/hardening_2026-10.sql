-- Hardening Copia Commissioni (progetto Supabase "preventivi")
-- Eseguito il 23/10/2026. Idempotente. Non modifica dati ne' righe esistenti.

-- 1) authenticated: via TRUNCATE (aggira la RLS), REFERENCES e TRIGGER
revoke truncate, references, trigger on
public.clienti, public.documenti, public.listino_items,
public.listino_log, public.listino_unita
from authenticated;

-- 2) listino_log: il client la legge soltanto (policy gia' solo SELECT)
revoke insert, update, delete on public.listino_log from authenticated;

-- 3) Funzioni trigger: non devono essere richiamabili dall'API
revoke execute on function public.guard_locked() from public, anon, authenticated;
revoke execute on function public.listino_touch() from public, anon, authenticated;
revoke execute on function public.unita_touch() from public, anon, authenticated;
revoke execute on function public.clienti_touch() from public, anon, authenticated;

-- 4) Storage: lettura allegati solo per proprietario, team e membri del documento
drop policy if exists "allegati_read" on storage.objects;
create policy "allegati_read" on storage.objects for select to authenticated
using (bucket_id = 'allegati' and exists (
  select 1 from public.documenti d
  where d.id = split_part(name, '/', 1)
  and (d.owner = auth.uid() or public.is_team() or public.is_member(d.id))));

-- 5) Storage: solo PDF, max 5 MB (come i limiti dell'app). Valgono per i nuovi caricamenti.
update storage.buckets
set file_size_limit = 5242880, allowed_mime_types = array['application/pdf']
where id in ('allegati', 'firmati');

-- Nota: il bucket "allegati" resta pubblico per URL (l'app usa il link pubblico).
-- Per renderlo privato servono link firmati a tempo nel codice dell'app.

-- 6) MODELLO per ogni tabella nuova creata dal 30/10/2026
-- (Supabase non concede piu' i grant in automatico)
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
