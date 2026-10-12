-- ============================================================
-- 탄소중립 도장판 · Supabase 설정
-- Supabase 대시보드 > SQL Editor 에 전체를 붙여 넣고 한 번 실행하세요.
-- 다시 실행해도 되도록 작성했습니다.
--
-- 실행한 뒤 대시보드에서 할 일
--   1) Authentication > Sign In / Providers > "Allow anonymous sign-ins" 켜기
--      (학생은 계정 없이 익명 로그인으로 접속합니다)
--   2) Authentication > Rate Limits > 익명 로그인 한도 올리기
--      기본값은 같은 IP에서 1시간에 30번입니다. 학교 와이파이는 IP가 하나라서
--      한 반이 동시에 처음 접속하면 막힐 수 있습니다. 학생 수보다 넉넉하게 올리세요.
--   3) Authentication > Users > Add user 로 교사 계정(이메일 + 비밀번호) 만들기
--   4) 이 파일 맨 아래의 "교사 등록" 문장에 그 이메일을 넣어 실행하기
--   5) Settings > API Keys 에서 Project URL 과 Publishable key 를 config.js 에 넣기
--      (sb_secret_ 로 시작하는 Secret key 는 절대 넣지 마세요)
-- ============================================================

-- ---------- 표 ----------
create table if not exists public.students (
  user_id     uuid primary key default auth.uid() references auth.users (id) on delete cascade,
  grade       smallint not null check (grade between 1 and 3),
  class_no    smallint not null check (class_no between 1 and 20),
  student_no  smallint not null check (student_no between 1 and 50),
  name        text not null check (char_length(name) between 1 and 20),
  created_at  timestamptz not null default now()
);

create table if not exists public.entries (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null default auth.uid() references public.students (user_id) on delete cascade,
  -- 도장 날짜는 서버가 한국 시간으로 정합니다. 기기 시계를 바꿔도 하루 1개입니다.
  day         date not null default ((now() at time zone 'Asia/Seoul')::date),
  category    text not null check (category in ('climate', 'local', 'mile', 'life')),
  mission     text not null check (char_length(mission) between 1 and 200),
  memo        text not null default '' check (char_length(memo) <= 300),
  photo_path  text not null,
  created_at  timestamptz not null default now(),
  unique (user_id, day)
);

-- 예전 버전의 이 파일을 이미 실행했다면: 학년 기본값(3)을 없앱니다. 학생이 직접 고릅니다.
alter table public.students alter column grade drop default;

create index if not exists entries_day_idx on public.entries (day);

-- 교사 목록. 여기에 들어 있는 계정만 모든 학생의 기록을 볼 수 있습니다.
create table if not exists public.teachers (
  user_id uuid primary key references auth.users (id) on delete cascade
);

-- ---------- 교사 확인 함수 ----------
create or replace function public.is_teacher()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.teachers t where t.user_id = (select auth.uid()));
$$;

revoke all on function public.is_teacher() from public;
grant execute on function public.is_teacher() to authenticated;

-- ---------- 행 수준 보안(RLS) ----------
alter table public.students enable row level security;
alter table public.entries  enable row level security;
alter table public.teachers enable row level security;   -- 정책 없음: 브라우저에서는 읽거나 쓸 수 없음

drop policy if exists "students: read own or teacher" on public.students;
create policy "students: read own or teacher" on public.students
  for select to authenticated
  using (user_id = (select auth.uid()) or (select public.is_teacher()));

drop policy if exists "students: insert own" on public.students;
create policy "students: insert own" on public.students
  for insert to authenticated
  with check (user_id = (select auth.uid()));

drop policy if exists "students: update own" on public.students;
create policy "students: update own" on public.students
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

drop policy if exists "entries: read own or teacher" on public.entries;
create policy "entries: read own or teacher" on public.entries
  for select to authenticated
  using (user_id = (select auth.uid()) or (select public.is_teacher()));

-- 자기 이름으로, 오늘 날짜로, 자기 폴더의 사진으로만 올릴 수 있음
drop policy if exists "entries: insert own today" on public.entries;
create policy "entries: insert own today" on public.entries
  for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and day = (now() at time zone 'Asia/Seoul')::date
    and photo_path like (select auth.uid())::text || '/%'
  );

drop policy if exists "entries: delete own or teacher" on public.entries;
create policy "entries: delete own or teacher" on public.entries
  for delete to authenticated
  using (user_id = (select auth.uid()) or (select public.is_teacher()));

grant select, insert, update on public.students to authenticated;
grant select, insert, delete on public.entries  to authenticated;

-- ---------- 교사용 요약 보기 ----------
create or replace view public.student_summary
with (security_invoker = true) as
  select s.user_id, s.grade, s.class_no, s.student_no, s.name,
         count(e.id)::int as stamps,
         max(e.day)       as last_day
  from public.students s
  left join public.entries e on e.user_id = s.user_id
  group by s.user_id;

grant select on public.student_summary to authenticated;

-- ---------- 사진 저장소 ----------
-- 비공개 버킷. 사진은 로그인한 본인과 교사만 볼 수 있습니다.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('photos', 'photos', false, 2097152, array['image/jpeg'])
on conflict (id) do update
  set public = excluded.public,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "photos: upload to own folder" on storage.objects;
create policy "photos: upload to own folder" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'photos'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "photos: read own or teacher" on storage.objects;
create policy "photos: read own or teacher" on storage.objects
  for select to authenticated
  using (
    bucket_id = 'photos'
    and ((storage.foldername(name))[1] = (select auth.uid())::text or (select public.is_teacher()))
  );

drop policy if exists "photos: delete own or teacher" on storage.objects;
create policy "photos: delete own or teacher" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'photos'
    and ((storage.foldername(name))[1] = (select auth.uid())::text or (select public.is_teacher()))
  );

-- ============================================================
-- 교사 등록
-- Authentication > Users 에서 교사 계정을 만든 뒤, 아래 이메일을 바꾸고
-- 앞의 "-- " 를 지워 이 두 줄만 실행하세요. 교사가 여러 명이면 반복합니다.
-- ============================================================
-- insert into public.teachers (user_id)
-- select id from auth.users where email = 'teacher@example.com' on conflict do nothing;
