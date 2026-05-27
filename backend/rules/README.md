# EDR 통합 보안 대시보드 v4 (완성형)

## 🎯 v4의 핵심 변경사항 (vs v3)

| 항목 | v3 | **v4** |
|---|---|---|
| 인증 헤더 | ~~`Authorization: Bearer`~~ ❌ | **`X-Session-Token`** ✅ |
| 데모 모드 | 옵션 (`DEMO_MODE = true/false`) | **`false` 고정** (완성형) |
| 자동 격리 토글 | UI만 있음 (작동 X) | **실제 작동** ✅ |
| 자동 IP 차단 토글 | UI만 있음 (작동 X) | **실제 작동** ✅ |
| 자동 프로세스 종료 | UI만 있음 (작동 X) | **실제 작동** ✅ |
| 권장 결정 표시 | 없음 | 인시던트 카드에 `권장: QUARANTINE` 배지 + 권장 버튼에 ★ 강조 |
| 자동 대응 이력 | 없음 | 설정 화면에 실행 이력 누적 표시 |

---

## 🔑 결정적 백엔드 분석 결과

`backend/main.py` 다시 정독하면서 v3의 치명적 오류를 발견했습니다.

### ❌ v3의 잘못 (인증 안 통하던 이유)

```python
# backend/main.py:127
def require_auth(x_session_token: str | None = Header(default=None, alias="X-Session-Token")):
```

백엔드는 **`X-Session-Token` 헤더만** 받습니다. v3가 사용하던 `Authorization: Bearer ...`는 **무시되어 401 에러**를 냈습니다.

### ✅ v4 수정

```javascript
function fetchAuthed(path, options = {}) {
    const opts = { ...options };
    opts.headers = {
        ...(opts.headers || {}),
        'X-Session-Token': authToken    // ✅ 올바른 헤더
    };
    return fetch(API_URL + path, opts);
}
```

### 자동 대응 정책의 실제 작동 원리

백엔드는 새 인시던트를 처리할 때 다음을 자동 계산합니다 (`backend/main.py:577-584`):

```python
if yara_result and yara_result.get("status") == "matched" and file_path:
    decision_hint = "quarantine"          # YARA 매칭 + 파일 존재 → 격리 권장
elif alert_fields.get("process_id") and risk_score >= 70:
    decision_hint = "terminate_process"   # 프로세스 ID 있고 위험 70+ → 종료 권장
elif alert_fields.get("destination_ip") and risk_score >= 70:
    decision_hint = "block_ip"            # 의심 IP + 위험 70+ → 차단 권장
else:
    decision_hint = "keep"
```

그리고 WebSocket으로 다음과 같은 메시지를 보냅니다:
```
[Response] Risk HIGH (85) | Suggested decision: QUARANTINE | ...
```

**v4 자동 대응 로직**:
1. WebSocket으로 들어온 `response` 메시지에서 `Suggested decision: XXX` 파싱
2. 해당 정책 토글이 켜져 있는지 확인
3. 켜져 있으면 0.8초 후 `/api/incidents`를 조회해 가장 최근 pending 인시던트 찾기
4. `suggested_decision`이 일치하면 `POST /api/incidents/{id}/decision`으로 자동 액션
5. 결과를 설정 화면의 "자동 대응 실행 이력"에 누적 + 토스트 표시
6. 중복 방지: `processedIncidentIds` Set으로 이미 처리한 인시던트는 다시 안 함

---

## 📋 7개 사이드바 메뉴 - 백엔드 연동 완전 매핑

### 1. **대시보드** ▦
- WebSocket `/ws/logs?token=...`로 실시간 이벤트 누적
- `/api/incidents` (10초 polling)로 활성 위협 수 갱신
- KPI 5종 / 도넛 / 24시간 타임라인 / 최근 이벤트 / 엔진별 바차트 모두 실시간

### 2. **이벤트 타임라인** ≡
- 메모리(최대 500건)에서 필터링 (심각도 / 엔진 / 키워드 검색)
- 클릭 시 상세 모달
- 백엔드 호출 없음 (이미 받은 데이터를 효율적으로 표시)

### 3. **실시간 탐지** ◉
- `POST /api/wazuh/start` / `/api/wazuh/stop`
- `POST /api/yara/start` / `/api/yara/stop` (body 없으면 로컬 룰)
- `GET /api/status` (8초마다 폴링)
- 라이브 콘솔 2개 (Wazuh / YARA 분리) + 상태 배너 3단계 변화

### 4. **분석 결과** ▲
- `GET /api/yara/directories` 트리 로드
- `GET /api/yara/directories/children?path=...` 하위 폴더 확장
- `POST /api/yara/start` (body: `{target_paths, rule_source: 'external'}`)
- YARA MATCH 결과 자동 누적

### 5. **위협 탐지** !
- `GET /api/incidents` 인시던트 목록
- `POST /api/incidents/{id}/decision` (action: quarantine/terminate_process/block_ip/keep)
- `POST /api/incidents/{id}/open-folder` 폴더 열기
- **권장 결정 시각화**: 백엔드의 `suggested_decision` 필드를 카드 헤더에 배지로 + 해당 버튼에 ★

### 6. **보고서** ▤
- `GET /api/logs` 로그 목록 (관리자는 `?username=...` 옵션)
- `GET /api/logs/{source}/{date}` 특정 날짜 로그 내용
- `POST /api/logs/{source}/{date}/clear` 날짜별 삭제
- `POST /api/logs/clear` 전체 삭제
- 관리자는 `GET /api/users`로 사용자 목록 가져와서 필터 가능

### 7. **설정** ⚙
- 계정 정보 (`/api/auth/me` 결과 + localStorage)
- 알림 설정 (브라우저 데스크톱 알림 권한 요청)
- **자동 대응 정책 3종** (자동 격리 / IP 차단 / 프로세스 종료) — localStorage에 저장
- **자동 대응 실행 이력** (최대 30건)
- 관리자 사용자 관리 (`/api/users`)

---

## 🤖 자동 대응 정책 사용법

### 시나리오 예시: "Cobalt Strike 발견 시 자동 격리"

1. 설정 → "Critical 탐지 시 자동 격리" 토글 켜기 → 토스트 "자동 격리가 활성화되었습니다"
2. 백엔드에서 Wazuh가 새 위협을 탐지하면:
   ```
   [Wazuh] Suspicious file detected: C:\Users\admin\Downloads\malicious.exe
   [Yara DETECT] Malware.Win32.Generic matched - Cobalt_Strike_Beacon_v4
   [Response] Risk HIGH (85) | Suggested decision: QUARANTINE | Isolate the affected endpoint
   ```
3. 프론트엔드가 `Suggested decision: QUARANTINE` 인식 → 800ms 후 인시던트 조회
4. 가장 최근 pending 인시던트의 `suggested_decision === 'quarantine'` 확인
5. `POST /api/incidents/{id}/decision` body: `{action: 'quarantine'}` 자동 호출
6. 백엔드의 `quarantine_incident_file()`이 파일을 격리 폴더로 이동
7. 결과:
   - 토스트: "🤖 자동 격리 실행됨: 파일이 격리되었습니다"
   - 설정 화면 이력에 `✓ 자동 격리 · 02:52:27 · C:\Users\admin\Downloads\malicious.exe`
   - 위협 탐지 뷰의 해당 인시던트가 "격리 완료" 상태로 변경

### 안전장치

- **중복 실행 방지**: `processedIncidentIds` Set으로 같은 인시던트에 두 번 액션 안 함
- **토글 OFF면 작동 안 함**: 각 정책은 독립적으로 켜고 끔
- **권장 결정만 트리거**: 백엔드가 권장한 액션만 자동 실행 (오작동 방지)
- **이력 추적**: 모든 자동 대응이 설정 화면에 기록되어 사후 검증 가능

---

## 📂 적용 방법

```
capston/
├── README.md              ← 이 파일 (선택)
├── backend/
│   └── main.py            ← 수정 안 함
└── frontend/
    ├── index.html         ← v4로 교체
    ├── style.css          ← v4로 교체
    └── app.js             ← v4로 교체
```

### Git 커밋 예시
```bash
cd /path/to/capston
cp /downloaded/frontend/*.{html,css,js} frontend/
git add frontend/
git commit -m "v4: 완성형 - X-Session-Token 인증, 자동 대응 정책 작동"
git push
```

---

## 🔧 백엔드 실행 확인

자동 대응이 작동하려면 백엔드의 다음 함수들이 실제로 동작해야 합니다:

| 함수 | 위치 | 역할 |
|---|---|---|
| `quarantine_incident_file()` | main.py:429 | 파일을 격리 폴더로 이동 |
| `terminate_incident_process()` | main.py:464 | PID로 프로세스 강제 종료 |
| `block_incident_ip()` | main.py:490 | 방화벽에 IP 차단 규칙 추가 |

이 함수들은 OS 권한이 필요할 수 있습니다:
- 격리: 격리 폴더 쓰기 권한
- 프로세스 종료: 관리자 권한 (Windows: `os.kill()`)
- IP 차단: Windows Firewall 또는 iptables 권한

백엔드를 **관리자 권한**으로 실행하지 않으면 자동 대응이 실패해서 "❌ 자동 대응 실패" 이력이 남을 수 있습니다.

---

## 📷 스크린샷

- `v4_1_설정_자동대응.png` — 자동 대응 정책 토글 + 실행 이력
- `v4_2_위협탐지_권장.png` — 권장 결정 배지 + ★ 강조 버튼
- `v4_3_대시보드.png` — 메인 대시보드

---

## 🐛 알려진 제약

1. **자동 대응은 *권장* 인시던트만 처리**: 백엔드가 `suggested_decision = keep`으로 판단하면 토글이 켜져 있어도 자동 실행 안 함
2. **WebSocket 끊김**: 자동 대응은 WebSocket의 response 메시지를 트리거로 사용. 연결이 끊겨 있으면 폴링으로는 자동 대응 안 됨 (이건 의도된 동작 — 끊긴 상태에서 자동 대응하면 위험)
3. **첫 로그인 시 토큰 형식**: 백엔드가 응답 body에서 `token` / `access_token` / `session_token` 중 어떤 키를 쓰는지에 따라 자동 시도. 셋 다 비어있으면 "서버 응답에 토큰이 없습니다" 에러
