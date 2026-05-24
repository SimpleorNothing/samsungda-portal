# 기획 도구 모음 — 디자인 스타일 가이드

`public/index.html`에 정의된 디자인 토큰과 스타일을 정리한 문서입니다.
신규 화면·컴포넌트를 만들 때 아래 값을 기준으로 통일합니다.

---

## 1. 컬러 팔레트 (CSS 변수)

`:root`에 정의된 6개 토큰으로 전체 색을 관리합니다.

| 토큰 | 값 | 용도 |
|---|---|---|
| `--bg` | `#ffffff` | 페이지 배경 (흰색) |
| `--surface` | `#f6f7f9` | 카드 바탕 (연회색) |
| `--text` | `#1a1d21` | 본문·제목 (거의 검정) |
| `--muted` | `#5b6470` | 보조 설명·날짜 (회색) |
| `--border` | `#e6e9ee` | 테두리·구분선 (연회색) |
| `--brand` | `#1257d6` | 강조·hover·링크 (파랑) |

**보조 색 (변수 밖)**

| 위치 | 값 |
|---|---|
| 삭제 버튼 기본 배경 | `#eef1f5` |
| 삭제 버튼 hover 배경 | `#ffe1e1` |
| 삭제 버튼 hover 글자 | `#c0392b` |

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
| 페이지 제목 | `h1` | **30px** | 800 | -0.5px | text |
| 페이지 부제 | `.sub` | 15px | 400 | — | muted |
| 섹션 제목 | `h2` | **20px** | 700 | -0.3px | text |
| 섹션 설명 | `.desc` | 13px | 400 | — | muted |
| 카드 제목 | `.card h3` | 17px | 700 | — | text |
| 카드 본문 | `.card p` | 13px | 400 | 행간 1.65 | muted |
| 카드 화살표 `→` | `h3::after` | 14px | — | 투명도 0.4 | text |
| 드롭존 안내 | `.dropzone` | 14px | 400 | — | muted |
| 업로드 상태·날짜 | `.upload-status` / `.updated` | 13px | 400 | — | muted |

**규칙**

- 큰 제목일수록 굵게(800 → 700) + 자간을 좁힘(−0.5 → −0.3px).
- 보조 텍스트는 전부 **13px · muted 색**으로 통일.

---

## 4. 도형 스타일 (Shapes)

### 카드 (`.card`) — 핵심 컴포넌트

- 바탕: `--surface` (연회색 `#f6f7f9`)
- 테두리: `1.5px solid --border`
- 모서리: **radius 14px** (라운드 네모)
- 안쪽 여백: `26px 22px` (상하 · 좌우)
- hover: 테두리 → 파랑(`--brand`) + 그림자 `0 4px 18px rgba(18,87,214,.10)`

### 라운드 radius 체계

| 값 | 적용 대상 |
|---|---|
| `14px` | 카드 · 드롭존 · 클릭 영역 (큰 박스) |
| `7px` | 삭제(×) 버튼 (작은 요소) |

### 드롭존 (`.dropzone`)

- 점선 테두리 `1.5px dashed --border`, radius 14px, padding 22px
- 드래그 중(`.is-over`): 파랑 테두리 + 옅은 파랑 배경 `rgba(18,87,214,.06)`

### 삭제 버튼 (`.research-del`)

- 24×24px, radius 7px, 기본 배경 `#eef1f5`
- 평소 숨김(opacity 0) → 카드 hover 시 노출

### 구분선

- `.updated` 상단에 `1px solid --border`.

---

## 5. 정렬 · 레이아웃

| 항목 | 값 |
|---|---|
| 기본 텍스트 정렬 | **왼쪽(left)** |
| 드롭존 텍스트 | **가운데(center)** |
| 카드 화살표 `→` | `margin-left:auto`로 우측 끝 정렬 (flex) |
| 본문 폭 | `.wrap` 최대 **860px**, 중앙 정렬 |
| 페이지 여백 | `body` 패딩 `56px 24px` |
| 그리드 | 3열 `repeat(3, 1fr)`, 간격 14px |
| 반응형 | **600px 이하 → 2열** |
| 섹션 간격 | `margin-bottom 40px` |

---

## 6. 인터랙션 (전환 효과)

- 카드 / 드롭존 hover: `transition .15s` (테두리 · 그림자 · 배경)
- 삭제 버튼: `transition .12s`
- 드래그 카드(`.is-dragging`): 그림자 `0 14px 34px rgba(18,87,214,.22)`, 커서 `grabbing`

---

## 요약

핵심 패턴은 다음과 같습니다.

> **흰 배경 + 연회색 라운드(14px) 카드 + 파랑(`#1257d6`) 강조 + 왼쪽 정렬 + 13px muted 보조텍스트**
