# 삼성DA 기획 도구 포털

기획팀 업무용 자동화 도구와 조사 결과물을 한곳에서 관리하는 내부 포털입니다.  
Cloudflare Workers + R2 + (선택) D1으로 구성됩니다.

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **사이트 비밀번호 게이트** | `SITE_PASSWORD` 설정 시 전체 페이지를 비밀번호로 보호. 180일 쿠키 유지 |
| **자동화 도구 링크 모음** | 보고서 자판기, Market Insight, 2030 미래 트렌드 등 링크 카드 |
| **조사 결과물 업로드/관리** | 파일 드래그&드롭 업로드 → Cloudflare R2 저장. 파일별 삭제 비밀번호 |
| **백엔드 프록시** | 나머지 경로는 Railway 백엔드로 투명하게 프록시 |
| **접속 로그** | D1 연결 시 `/__logs` 에서 날짜별 방문자 통계 조회 (선택) |

---

## 기술 스택

- **런타임**: [Cloudflare Workers](https://workers.cloudflare.com/)
- **정적 자산**: Cloudflare Workers Static Assets (`public/`)
- **파일 저장**: Cloudflare R2 (`samsungda-research` 버킷)
- **접속 로그 DB**: Cloudflare D1 (선택)
- **백엔드**: Railway (`BACKEND_UPSTREAM`)

---

## 프로젝트 구조

```
samsungda-portal/
├── public/
│   └── index.html        # 포털 메인 페이지 (프론트엔드 전체)
├── src/
│   └── index.js          # Cloudflare Worker (인증·API·프록시 로직)
├── migrations/
│   └── 0001_access_log.sql  # D1 접속 로그 테이블 스키마
├── wrangler.jsonc         # Cloudflare 배포 설정
└── .dev.vars.example      # 로컬 개발용 환경변수 예시
```

---

## 로컬 개발 환경 설정

### 1. 사전 준비

```bash
npm install -g wrangler
```

### 2. 환경변수 설정

```bash
cp .dev.vars.example .dev.vars
```

`.dev.vars` 파일을 열어 값을 수정합니다:

```env
SITE_PASSWORD=원하는_비밀번호   # 사이트 접근 비밀번호
UPLOAD_TOKEN=change-me          # 레거시 파일 삭제용 (신규 파일은 불필요)
```

### 3. 개발 서버 실행

```bash
wrangler dev
```

> R2 버킷 없이 실행하면 파일 업로드 기능은 503을 반환합니다.  
> D1 없이 실행하면 접속 로그 기능은 자동으로 비활성화됩니다.

---

## 배포

```bash
wrangler deploy
```

### 필수 Cloudflare 리소스

| 리소스 | 설정 방법 |
|--------|-----------|
| R2 버킷 | `wrangler r2 bucket create samsungda-research` |
| `SITE_PASSWORD` 시크릿 | `wrangler secret put SITE_PASSWORD` |

### 접속 로그(선택)

D1을 연결하면 `/__logs`에서 날짜별 방문자 현황을 볼 수 있습니다.

```bash
wrangler d1 create samsungda-access-logs
```

생성 후 출력된 `database_id`를 `wrangler.jsonc`의 주석 처리된 `d1_databases` 블록에 입력하고 주석을 해제한 뒤 재배포합니다.

---

## API 엔드포인트

| 메서드 | 경로 | 설명 |
|--------|------|------|
| `GET` | `/api/research` | 업로드된 파일 목록 조회 |
| `POST` | `/api/research` | 파일 업로드 (multipart/form-data) |
| `DELETE` | `/api/research/:id` | 파일 삭제 (헤더: `x-file-password`) |
| `GET` | `/research/:id` | 파일 다운로드 |
| `GET` | `/__logs` | 접속 로그 (D1 연결 시) |

---

## 보안 참고

- 사이트 비밀번호는 HMAC-SHA256 서명 쿠키로 검증합니다.
- 비밀번호를 변경하면 기존 쿠키가 자동 무효화됩니다.
- 파일 삭제는 업로드 시 설정한 **파일별 비밀번호**가 필요합니다 (PBKDF2 해시 저장).
- 업로드 파일은 `sandbox` CSP로 격리되어 포털의 스토리지·쿠키에 접근할 수 없습니다.
