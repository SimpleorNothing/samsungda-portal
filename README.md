# samsungda-portal — 기획 도구 모음 (samsungda.net)

DA 기획팀의 자동화 도구와 조사 결과물을 한곳에 모은 **포털 허브**입니다.
사이트 전체를 비밀번호로 보호하는 단일 **Cloudflare Worker**로, 정적 포털 페이지·조사 결과물 저장소(R2)·접속 로그(D1)를 직접 처리하고, 나머지 요청은 백엔드(Railway/FastAPI, `report-site`)로 경로 그대로 프록시합니다.

- **URL:** `https://samsungda.net`
- **런타임:** Cloudflare Workers (`wrangler.jsonc`, `name = samsungda-portal`)
- **정적 자산:** `public/index.html` — `run_worker_first: true`로 루트(`/`)에도 비밀번호 게이트 적용
- **백엔드:** `BACKEND_UPSTREAM` → `report-site` (FastAPI on Railway)

---

## 수록 도구 (기획 도구 모음)

포털 첫 화면 "자동화 도구 모음" 카드와 동일한 라인업입니다. 이 표가 곧 포털의 캐노니컬 가이드이며, 각 산하 레포 README도 이 표를 공유합니다.

| 도구 | 진입 | 설명 | 백엔드 레포 |
|------|------|------|-------------|
| 클로드로 워드보고서 작성하기 | `/agent-guide` | Claude AI 에이전트 활용법과 실전 예제 가이드 | `report-site` |
| 보고서 자판기 | `/report` | 지시문을 입력하면 AI가 보고서(DOCX)를 자동 작성 | `report-site` |
| Market Insight | `mi.samsungda.net` | 시장 동향과 인사이트 분석·정리 | `market-insight` |
| 2030 미래 트렌드 | `/2030` | 2030년 미래 트렌드 전망과 시나리오 분석 | (외부 연동) |
| Quick Share | `quickshare.samsungda.net` | 파일을 빠르게 공유·전달 | `QuickShare` |
| My Space | `space.samsungda.net` | 누구나 쓰는 공유 작업 공간 | `samsungda-space` |

두 번째 섹션 "조사 결과물 모음"은 Claude로 작성한 보고서를 업로드·검색·다운로드하는 파일 목록으로, 이 Worker가 R2 버킷(`samsungda-research`)에서 직접 서빙합니다.

---

## Worker가 직접 처리하는 경로

| 경로 | 메서드 | 동작 |
|------|--------|------|
| `/`, `/index.html` | GET | 포털 페이지(정적 자산) |
| `/__auth` | POST | 비밀번호 로그인 → 세션 쿠키 발급 |
| `/__logs` | GET | 접속 로그 조회(관리자, KST 기준 일별 고유 방문자) |
| `/api/research` | GET·POST | 조사 결과물 목록 / 업로드 |
| `/api/research/<id>` | DELETE | 조사 결과물 삭제(파일별 비밀번호) |
| `/research/<id>` | GET | 업로드된 결과물 열람(샌드박스 CSP 격리) |
| 그 외 전체 | * | `BACKEND_UPSTREAM`(Railway)으로 경로 그대로 프록시 |

---

## 접근 보호 (비밀번호 게이트)

- `SITE_PASSWORD`가 설정되면 사이트 전체가 보호됩니다. 최초 1회 입력 후 세션 쿠키(`da_portal_session`)로 약 180일 유지.
- 세션 토큰은 현재 비밀번호에서 HMAC으로 파생 — **비밀번호를 바꾸면 기존 쿠키가 자동 무효화**됩니다.
- 오픈 리다이렉트 차단(`next`는 동일 출처 경로만 허용), 비밀번호 비교는 타이밍 세이프 방식.

## 조사 결과물 저장 (R2)

- 버킷 바인딩 `RESEARCH` → `samsungda-research`.
- 업로드 시 **삭제 비밀번호**를 PBKDF2(SHA-256, 10만 회)로 해시해 메타데이터에 저장 — 평문은 어디에도 저장하지 않음.
- 다운로드는 업로드 당시 원본 파일명(`content-disposition`)으로 내려가고, 열람은 샌드박스 CSP로 격리되어 포털 쿠키·스토리지에 접근할 수 없습니다.

## 접속 로그 (선택, D1)

- `ACCESS_LOG` D1 바인딩이 연결되면 요청마다 시각·IP·브라우저·경로를 기록합니다(`/__` 내부 경로 제외).
- 날짜 경계는 **한국시간(KST)** 기준이며, 첫 기록 시 테이블이 자동 생성됩니다(별도 마이그레이션 실행 불필요).
- 바인딩이 없으면 로깅은 자동 비활성화되고 사이트는 정상 동작합니다.
- 켜는 법: `wrangler d1 create samsungda-access-logs` → `wrangler.jsonc`의 `d1_databases` 블록 주석 해제 후 `database_id` 입력 → 배포.

---

## 디렉토리 구조

```
samsungda-portal/
├── src/index.js          # Worker: 게이트·접속 로그·조사 결과물 API·백엔드 프록시
├── public/
│   └── index.html        # 포털 페이지(도구 카드 + 조사 결과물 목록)
├── migrations/           # D1 마이그레이션(접속 로그)
├── STYLE_GUIDE.md        # 디자인 토큰·레이아웃 규약
├── wrangler.jsonc        # name·assets·vars·R2/D1 바인딩
└── .dev.vars.example     # 로컬 비밀값 예시
```

## 환경 변수 / 바인딩

| 이름 | 종류 | 용도 |
|------|------|------|
| `SITE_PASSWORD` | Secret | 사이트 접근 비밀번호(게이트) |
| `BACKEND_UPSTREAM` | Var | 백엔드(Railway) 주소 — 미지정 경로 프록시 대상 |
| `RESEARCH` | R2 | 조사 결과물 저장(`samsungda-research`) |
| `ACCESS_LOG` | D1 | 접속 로그(선택) |

> 로컬 개발 시 비밀값은 `.dev.vars`(`.dev.vars.example` 참고)에 둡니다.

## 로컬 실행 / 배포

```bash
npm install
npx wrangler login
npx wrangler dev          # http://localhost:8787
npx wrangler deploy       # wrangler.jsonc의 name 기준으로 samsungda-portal 워커에 배포
```

## 디자인 시스템

배경 `#ffffff` · 표면 `#f6f7f9` · 텍스트 `#1a1d21` · 보조 `#5b6470` · 보더 `#e6e9ee` · 브랜드 블루 `#1257d6`, Pretendard, 최대 폭 860px, 14px 라운드 카드, 3열 그리드(600px 이하 2열). 자세한 규약은 `STYLE_GUIDE.md` 참고.

---

## 생태계

> 🧭 **기획 도구 모음**(`samsungda.net`) 생태계의 일부입니다 — 허브 레포: [`samsungda-portal`](https://github.com/SimpleorNothing/samsungda-portal)

| 도구 | 진입 | 레포 |
|------|------|------|
| 클로드로 워드보고서 작성하기 | `samsungda.net/agent-guide` | `report-site` |
| 보고서 자판기 | `report.samsungda.net` | `report-site` |
| Market Insight | `mi.samsungda.net` | `market-insight` |
| 2030 미래 트렌드 | `samsungda.net/2030` | (외부 연동) |
| Quick Share | `quickshare.samsungda.net` | `QuickShare` |
| My Space | `space.samsungda.net` | `samsungda-space` |
