-- 접속 로그 테이블. Worker가 첫 접속 시 동일 스키마를 자동 생성하므로 이 파일을
-- 따로 실행하지 않아도 동작한다. 마이그레이션으로 관리하고 싶을 때만 사용한다:
--   wrangler d1 execute samsungda-access-logs --remote --file=./migrations/0001_access_log.sql
CREATE TABLE IF NOT EXISTS access_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,      -- 요청 시각(UTC, ISO 8601)
  day TEXT NOT NULL,     -- 한국시간(KST) 기준 날짜 YYYY-MM-DD (날짜별 집계용)
  ip TEXT,               -- CF-Connecting-IP
  ua TEXT,               -- User-Agent 원문(최대 300자)
  browser TEXT,          -- UA에서 추출한 브라우저 종류
  path TEXT,             -- 요청 경로
  method TEXT,           -- HTTP 메서드
  country TEXT           -- Cloudflare 추정 국가코드
);
CREATE INDEX IF NOT EXISTS idx_access_day ON access_log(day);
