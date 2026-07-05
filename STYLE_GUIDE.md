# 기획 도구 모음 — 디자인 스타일 가이드

`public/index.html`에 정의된 디자인 토큰과 스타일을 정리한 문서입니다.
신규 화면·컴포넌트를 만들 때 아래 값을 기준으로 통일합니다.

> **2026-07 갱신 안내**: PR #116(포털에 CI 편집국 스타일 적용)로 팔레트가 교체되어 1장을 최신 토큰으로 갱신했습니다.
> 2~6장의 구성요소 설명(드롭존·삭제 버튼 등)은 그 이후 진행된 파이프라인 레이아웃 리디자인 이전 버전을 기준으로 작성되어 현재 `public/index.html` 구조와 다를 수 있습니다 — 구조 관련 세부값은 실제 소스를 함께 확인하세요. 생태계 전체의 컬러 트랙 현황은 8장을 참고합니다.

---

## 1. 컬러 팔레트 (CSS 변수)

`:root`에 정의된 CI 편집국 톤 토큰으로 전체 색을 관리합니다.

| 토큰 | 값 | 용도 |
|---|---|---|
| `--paper` | `#EDEFEC` | 페이지 배경 |
| `--panel` | `#ffffff` | 카드·패널 바탕 |
| `--ink` | `#17222D` | 본문·제목 |
| `--muted` | `#5C6B79` | 보조 설명·날짜 |
| `--line` | `#D3D9D6` | 테두리·구분선(연함) |
| `--line-strong` | `#9AA6A0` | 카드 테두리(진함) |
| `--new` | `#46647E` | 액센트 1(센싱) · `--brand` 레거시 별칭 |
| `--deep` | `#2F614D` | 액센트 2(인사이트) |
| `--purple` | `#6B4E9B` | 액센트 3(공유) |
| `--insight` | `#B02E24` | 경고·삭제·red 대체 |
| `--amber` | `#A9790F` | 강조 하이라이트(형광펜 등) |

`--brand`는 `var(--new)`로 유지되는 레거시 호환 별칭이며, 신규 코드는 `--new`를 직접 씁니다.

**예외 없음**: 과거 `2030-insight`(2030 미래 전망)만 센싱 리포트 성격상 Pantone 팔레트(`#F0EFEB` Cloud Dancer · `#496176` Blue Fusion 등)를 예외로 썼으나, 생태계 톤 통일을 위해 CI 팔레트로 전환되어 예외가 해소됐습니다. 이제 모든 도구가 CI 팔레트 트랙을 따릅니다. 자세한 내용은 8장 참고.

---

## 2. 글자체 (Typeface)

```css
font-family: 'Pretendard', system-ui, -apple-system, 'Segoe UI',
             Roboto, 'Apple SD Gothic Neo', 'Noto Sans KR', sans-serif;
```

- 메인 폰트는 **Pretendard**, 없으면 OS 기본 한글 폰트로 폴백합니다.
- ※ 웹폰트 파일을 따로 로드하지 않으므로 Pretendard는 설치된 기기에서만 적용됩니다.
  안정적으로 쓰려면 CDN `<link>` 또는 `@font-face` 추가가 필요합니다.

---

## 3. 글자 크기 · 굵기 (타이포 스케일)

| 역할 | 클래스 | 크기 | 굵기 | 자간 | 색 |
|---|---|---|---|---|---|
| 페이지 제목 | `h1` | **30px** | 800 | -0.5px | ink |
| 페이지 부제 | `.sub` | 15px | 400 | — | muted |
| 섹션 제목 | `h2` | **20px** | 700 | -0.3px | ink |
| 섹션 설명 | `.desc` | 15px | 400 | — | muted |
| 카드 제목 | `.card h3` | 17px | 700 | — | ink |
| 카드 본문 | `.card p` | 15px | 400 | 행간 1.65 | muted |
| 카드 화살표 `→` | `h3::after` | 14px | — | 투명도 0.4 | line-strong |

**규칙**

- 큰 제목일수록 굵게(800 → 700) + 자간을 좁힘(−0.5 → −0.3px).
- 보조 텍스트는 전사 폰트 표준(최소 15px)에 맞춰 **15px · muted 색**으로 통일.

---

## 4. 도형 스타일 (Shapes)

### 카드 (`.card`) — 핵심 컴포넌트

- 바탕: `--panel` (흰색)
- 테두리: `1px solid --line-strong`, 상단 3px는 단계별 `--accent`(new/deep/purple)
- 모서리: **radius 0** — CI 편집국 톤(각진 모서리)
- 안쪽 여백: `26px 22px` (상하 · 좌우)
- hover: 테두리 → `--ink` + 그림자 `0 2px 0 var(--accent, var(--ink))`

### 라운드 radius 체계

CI 편집국 톤에서는 카드·버튼 모두 **radius 0**(각진 모서리)을 기본으로 합니다.

---

## 5. 정렬 · 레이아웃

| 항목 | 값 |
|---|---|
| 기본 텍스트 정렬 | **왼쪽(left)** |
| 본문 폭 | `.wrap` 최대 **860px**, 중앙 정렬 |
| 페이지 여백 | `body` 패딩 `56px 24px` |
| 반응형 | **600px 이하 → 2열** |
| 섹션 간격 | `margin-bottom 40px` |

---

## 6. 인터랙션 (전환 효과)

- 카드 hover: `transition .2s ease`(테두리 · 그림자 · transform)
- 드래그 카드(`.is-dragging`): 그림자 `0 14px 34px rgba(23,34,45,.22)`, 커서 `grabbing`
- 형광펜 sweep: 앰버(`--amber`) 틴트, 진입 1회 + hover 재생

---

## 7. 요약

핵심 패턴은 다음과 같습니다.

> **연회색(`#EDEFEC`) 배경 + 흰 패널 + 각진(radius 0) 카드 + 단계별 액센트(new/deep/purple) + 왼쪽 정렬 + 15px muted 보조텍스트**

---

## 8. 생태계 컬러 트랙 레지스트리

기획도구 생태계 각 저장소가 어떤 컬러 트랙을 쓰는지 기록합니다. 신규 도구를 만들 때는 **CI 팔레트 트랙**을 기본으로 따르고, Pantone 예외를 다른 도구로 끌어오지 않습니다.

| 저장소 | 도구 | 트랙 | 비고 |
|---|---|---|---|
| `samsungda-portal` | 기획도구 모음(포털) | CI 팔레트 | 완료 — PR #116 |
| `market-insight` | Market Sensing | CI 팔레트 | 완료 |
| `samsungda-space` | My Space | CI 팔레트 | 완료 — PR #73 |
| `quickshare` | Quick Share | CI 팔레트 | 완료 — PR #49 |
| `2030-insight` | 2030 미래 전망 | CI 팔레트 | 완료 — Pantone 예외에서 전환 |
| `report-site` | 보고서 자판기 | 미전환 | 기존 팔레트(Apple 블루 계열) 유지 중 |
| `report-idea` | 아이디어 자판기 | 미전환 | — |
| `competitor_intelligence` | 경쟁사 전략 추적 | 미전환 | — |
| `samsungda-newsletter` | 뉴스레터 | 미전환 | — |
| `agent-guide` | 워드보고서 가이드 | 미전환 | — |

**CI 팔레트 트랙 공통 토큰**: `--paper #EDEFEC` · `--panel #fff` · `--ink #17222D` · `--muted #5C6B79` · `--line #D3D9D6` / `--line-strong #9AA6A0` · 액센트 `--new #46647E` / `--deep #2F614D` / `--purple #6B4E9B` · 상태색 `--insight #B02E24`(red 대체) / `--amber #A9790F`.
