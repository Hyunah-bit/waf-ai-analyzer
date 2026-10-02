# waf-ai-analyzer
"ModSecurity WAF logs dual-LLM cross-verification system for automated false positive detection"

# AI 기반 WAF 오탐·정탐 자동 판정 시스템

ModSecurity WAF가 차단한 로그를 **두 개의 LLM이 교차 검증**하여 정탐(실제 공격)인지 오탐(정상 요청)인지 자동 판별하고, 관리자가 검토해야 할 것만 골라 알림을 보내는 자동화 시스템입니다.

---

## 📌 프로젝트 개요

WAF는 룰에 걸리면 무조건 차단하지만, 그 차단이 **진짜 공격 때문인지 정상 요청을 오해한 것인지**는 구분하지 못합니다. 정상 사용자가 `web.config 책 있나요` 같은 검색을 해도 파일명이 룰에 걸려 차단되는 오탐이 발생합니다.

이 시스템은 사람이 로그를 일일이 확인하던 작업을 AI로 자동화합니다.

- **정탐(true_positive)**: 실제 공격 → 차단이 타당함
- **오탐(false_positive)**: 정상 요청인데 차단됨 → WAF의 과잉 차단
- **검토필요(needs_review)**: 두 AI 의견이 갈림 → 사람이 확인

### 핵심 특징

- **이중 LLM 교차 검증**: Gemini(1차)와 Groq(2차)이 각각 독립적으로 판정하고, 두 결과가 일치하면 신뢰하며 불일치하면 사람이 확인
- **자동화**: cron으로 주기적 분석, 검토 대상만 알림
- **민감정보 보호**: AI 전송 전 비밀번호·쿠키 마스킹
- **판정 이력 축적**: SQLite DB에 누적하여 SQL 조회 가능

---

## 🏗️ 시스템 구조

```
 [공격자]                                          [관리자]
    |                                                 ^
    | ① 요청                                           | ⑥ 검토 알림
    v                                                 |
 [WAF: ModSecurity + CRS]                       [alert_review]
    |  ② 룰 매칭 시 차단(403) + 로그 기록               ^
    v                                                 | ⑤ 검토필요/오탐 감시
 [modsec_audit.log] --③ 로그 읽기--> [waf_ai.py] ------+
    (JSON 로그)                            |
                                           | ④ AI 판정 후 저장
                                           v
                                    [waf_analysis.db]
                                       (SQLite)
```

### 판정 파이프라인

```
원본 로그 (JSON)
  → transaction_id로 신규 여부 확인 (중복 방지)
  → 차단된 건(intercepted)만 선별
  → 민감정보 마스킹
  → Gemini 1차 판정 (정탐/오탐/검토필요 + CWE + 근거)
  → Groq 2차 교차 검증
       ├ 일치   → 1차 판정 확정
       ├ 불일치 → needs_review (사람 확인)
       └ 실패   → 1차 판정 유지 + "검증 불가" 표시
  → SQLite 적재
  → 리포트 / 알림
```

---

## 🖥️ 실행 환경

| 구성요소 | 내용 |
|---|---|
| OS / 서버 | Ubuntu 20.04 / Apache 2.4.41 |
| WAF | ModSecurity 2.9.3 + OWASP CRS 3.3.2 (Paranoia Level 1) |
| 테스트 대상 | OWASP Juice Shop (리버스 프록시 뒤) |
| 1차 판정 AI | Google Gemini (REST API 직접 호출) |
| 2차 검증 AI | Groq (OpenAI 호환 API) |
| 언어 | Python 3.8+ (표준 라이브러리만 사용, SDK 불필요) |

> 리버스 프록시 구조로, 쇼핑몰로 가는 모든 요청은 반드시 WAF를 거칩니다.

---

## 📁 파일 구성

| 파일 | 역할 |
|---|---|
| `waf_ai.py` | 메인 로직 (로그 읽기 → AI 판정 → 교차 검증 → DB 저장 → 리포트) |
| `config.py` | 설정값 (API 키, 경로, 임계값, 배치 크기) |
| `prompt.txt` | AI 판정 프롬프트 |
| `alert_review.sh` | 검토필요/오탐만 감시하여 알림 (텔레그램 전송) |
| `waf_analysis.db` | 판정 결과 저장소 (SQLite, 자동 생성) |

---

## ⚙️ 설치 및 설정

### 1. 사전 준비

```bash
# ModSecurity 감사 로그를 JSON 형식으로 설정
# /etc/modsecurity/modsecurity.conf
SecAuditLogFormat JSON
SecAuditLogParts ABIJDFHKZ

sudo systemctl restart apache2

# sqlite3 설치 (알림 스크립트용)
sudo apt install sqlite3 -y
```

### 2. config.py 설정

`config.py`에 본인의 API 키를 입력합니다.

```python
# Gemini API (1차 판정) - https://aistudio.google.com/apikey
GEMINI_API_KEY = "본인_키_입력"
MODEL = "gemini-3.1-flash-lite"

# Groq API (2차 검증) - https://console.groq.com
GROQ_API_KEY = "본인_키_입력"
GROQ_MODEL = "openai/gpt-oss-120b"

# 파일 경로
LOG_FILE_PATH = "/var/log/apache2/modsec_audit.log"
DB_PATH = "waf_analysis.db"

# 판정 파라미터
FP_CONFIDENCE_THRESHOLD = 0.85   # 오탐 판정 최소 확신도
BATCH_SIZE = 3                   # 한 번에 묶어 판정할 로그 수
```

> ⚠️ **config.py는 API 키를 포함하므로 반드시 `.gitignore`에 추가하세요.**

### 3. 세 파일을 같은 폴더에

`waf_ai.py`, `config.py`, `prompt.txt`는 반드시 같은 디렉터리에 둡니다.

---

## 🚀 사용법

```bash
python3 waf_ai.py analyze    # 새 로그 분석 후 DB 적재
python3 waf_ai.py report     # 오늘자 리포트 출력
python3 waf_ai.py report 7   # 최근 7일 리포트
python3 waf_ai.py            # 분석 + 리포트 (cron용)
```

로그 파일 접근에 root 권한이 필요하면 `sudo`로 실행합니다.

### 자동화 (cron)

```bash
# 분석 + 하루치 리포트 (3분마다 - 테스트용)
*/3 * * * * cd /usr/local/bin && /usr/bin/python3 waf_ai.py >> /var/log/wafai_daily.log 2>&1

# 7일치 리포트 (매주 월요일 9시)
0 9 * * 1 cd /usr/local/bin && /usr/bin/python3 waf_ai.py report 7 >> /var/log/wafai_weekly.log 2>&1
```

### 검토 알림 (텔레그램)

`alert_review.sh`에 텔레그램 봇 토큰과 chat_id를 입력한 뒤 실행합니다.

```bash
sudo bash alert_review.sh
```

DB를 주기적으로 감시하다가 검토필요/오탐이 새로 생기면 텔레그램으로 알림을 보냅니다. (정탐은 무시)

---

## 📊 리포트 예시

```
==============================================================
  ModSecurity WAF AI 분석 리포트   2026-09-23 17:10
==============================================================

  총 12건 | 오탐 6  검토필요 0  정탐 6

--------------------------------------------------------------
  [오탐 후보 - 예외 규칙 검토 필요]  6건
--------------------------------------------------------------
  * SQL Injection 탐지 오탐   (확신도 95%)
    경로 : /rest/products/search?q=재료를 SELECT 해서...FROM...레시피북
    룰 ID: 942360
    근거 : SELECT, FROM이 포함돼 SQLi 룰에 걸렸으나,
           문맥상 요리 레시피 검색이며 SQL 구문으로 완결되지 않음
    ※ 검증 : 교차 검증 일치 (Gemini=Groq)

--------------------------------------------------------------
  [정탐]  6건
--------------------------------------------------------------
    CWE-22 (Path Traversal)  4건
    CWE-89 (SQL Injection)   2건
```

---

## 🔬 핵심 검증 로직

### 이중 LLM 교차 검증

서로 다른 두 LLM이 **각각 독립적으로** 로그를 판정합니다.

| 두 모델 결과 | 처리 | 의미 |
|---|---|---|
| 일치 | 판정 확정 | 두 AI가 같은 결론 → 신뢰도 높음 |
| 불일치 | needs_review | 의견 갈림 → 사람이 최종 확인 |
| 한쪽 응답 불가 | 1차 판정 유지 + 표시 | 교차 검증 불가 → 참고용 기록 |

단일 AI는 편향·환각 위험이 있으나, **다른 회사의 독립적인 모델**(Google Gemini ↔ Groq의 gpt-oss)로 교차 검증하면 한 모델의 실수를 다른 모델이 잡아낼 수 있습니다.

### "같은 룰, 다른 판정" — 시스템의 핵심 가치

같은 CRS 룰에 걸린 두 요청을 AI가 **내용을 보고** 다르게 판정합니다.

| CRS 룰 | 정상 요청 (오탐) | 실제 공격 (정탐) |
|---|---|---|
| 930120 (LFI) | `web.config 책 있나요` | `../../../web.config` |
| 942360 (SQLi) | `SELECT FROM 레시피북` | `' UNION SELECT password FROM Users--` |

**WAF는 룰만 보고 둘 다 차단하지만, AI는 내용을 보고 구분합니다.** 이것이 이 프로젝트의 핵심입니다.

---

## 🧱 설계 원칙

| 원칙 | 구현 |
|---|---|
| 중복 없이, 놓치지 않게 | transaction_id 기반 → 재실행·로테이트에 안전 |
| AI를 믿되 검증한다 | 이중 LLM 교차 검증으로 편향·환각 차단 |
| 민감정보 보호 | AI 전송 전 password·cookie 마스킹 |
| 관리자 편의 우선 | 검토 대상만 알림, 정탐은 요약 |

---

## ⚠️ 알려진 한계

- **WAF가 못 잡는 공격**: 접근권한(IDOR), 안전하지 않은 설계, 암호화 실패, 공급망 공격 등은 요청 페이로드에 특징이 없어 CRS 룰에 걸리지 않음 → 분석 대상이 아님. OWASP Top 10 중 요청 기반 탐지가 가능한 카테고리(접근통제, 설정오류, 인젝션, 무결성 등)가 대상
- **오탐 발생 빈도**: Paranoia Level 1은 느슨해서 오탐이 드묾. 자유 텍스트 필드에 공격 키워드가 우연히 든 경우에만 발생
- **API 한도**: 무료 등급 사용 시 분당 토큰 제한(Groq TPM 등)에 유의. 배치 크기로 조절

---

## 📄 라이선스

이 프로젝트는 교육·연구 목적으로 작성되었습니다.
