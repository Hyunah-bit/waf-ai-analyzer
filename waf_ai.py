#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ModSecurity audit.log -> AI 오탐/정탐 판정 -> SQLite 적재 -> 콘솔 리포트
(REST API 직접 호출 버전 — SDK 불필요, Python 3.8+ 표준 라이브러리만 사용)

파일 구성:
  config.py    설정값 (API 키, 경로, 임계값)
  prompt.txt   AI 프롬프트
  waf_ai.py    로직 (이 파일)
  -> 세 파일은 반드시 같은 폴더에 둘 것.

파일 위치: /usr/local/bin/

사용법:
  python3 waf_ai.py analyze    # 새 로그 분석 후 DB 적재
  python3 waf_ai.py report     # 오늘자 리포트 콘솔 출력
  python3 waf_ai.py report 7   # 최근 7일 리포트
  python3 waf_ai.py            # analyze + report 연속 실행 (cron용)
"""

import os
import re
import sys
import json
import time
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime, timedelta

import config   # <- 같은 폴더의 config.py

# ------------------------------------------------------------------ 초기 로드

# 이 스크립트 파일이 있는 폴더 (cron 등 어디서 실행해도 옆 파일을 찾도록)
HERE = os.path.dirname(os.path.abspath(__file__))

# 프롬프트를 prompt.txt 에서 읽어온다
with open(os.path.join(HERE, "prompt.txt"), encoding="utf-8") as _pf:
    PROMPT = _pf.read()

# Gemini 엔드포인트 (config 값으로 조립)
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/"
    "models/" + config.MODEL + ":generateContent?key=" + config.GEMINI_API_KEY
)

# Groq 엔드포인트 (2차 검증용, OpenAI 호환 API)
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

# ------------------------------------------------------------------ DB

def init_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis (
            transaction_id TEXT PRIMARY KEY,
            log_time       TEXT,
            client_ip      TEXT,
            client_port    TEXT,
            uri            TEXT,
            rule_ids       TEXT,
            verdict        TEXT,
            confidence     REAL,
            attack_name    TEXT,
            cwe_id         TEXT,
            cwe_name       TEXT,
            reason         TEXT,
            evidence       TEXT,
            validation     TEXT,
            raw_log        TEXT,
            analyzed_at    TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_analyzed_at ON analysis(analyzed_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_verdict ON analysis(verdict)")
    conn.commit()
    return conn


def loaded_ids(conn):
    """이미 분석 완료된 transaction_id 집합."""
    return {row[0] for row in conn.execute("SELECT transaction_id FROM analysis")}

# ------------------------------------------------------------------ 로그 읽기

def read_new_events(conn):
    """audit.log(JSONL)에서 아직 분석하지 않은 트랜잭션만 반환."""
    if not os.path.exists(config.LOG_FILE_PATH):
        print("[오류] 로그 파일 없음: " + config.LOG_FILE_PATH, file=sys.stderr)
        return []

    done = loaded_ids(conn)
    events = []

    with open(config.LOG_FILE_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # 기록 중인 마지막 줄이 잘렸을 수 있음 -> 다음 실행 때 다시 읽힘
                continue

            tid = obj.get("transaction", {}).get("transaction_id")
            if not tid or tid in done:
                continue

            # 차단된 건만 분석 (탐지만 하고 통과시킨 건 제외)
            if not obj.get("audit_data", {}).get("action", {}).get("intercepted"):
                continue

            events.append((tid, obj, line))
            done.add(tid)   # 같은 파일 내 중복 방지

    return events

# ------------------------------------------------------------------ 마스킹

MASK_PATTERNS = [
    # password=xxx, "password":"xxx", pwd: xxx
    (re.compile(r'("?(?:password|passwd|pwd|secret|token|api[_-]?key|otp)"?\s*[=:]\s*)"?([^&",}\s]+)"?', re.I),
     r'\1<MASKED>'),
    # "Cookie": "...", "Authorization": "..."
    (re.compile(r'("(?:Cookie|Set-Cookie|Authorization|X-Api-Key)"\s*:\s*)"[^"]*"', re.I),
     r'\1"<MASKED>"'),
]

def mask(text):
    for pattern, repl in MASK_PATTERNS:
        text = pattern.sub(repl, text)
    return text

# ------------------------------------------------------------------ 메타 추출
# (판정은 AI가 로그 원문으로 하고, 아래는 DB 컬럼 채우기용)

RULE_ID_RE = re.compile(r'\[id "(\d+)"\]')
SCORING_RULES = {"949110", "949111", "980130", "980140"}

def extract_meta(obj):
    tx = obj.get("transaction", {})
    req = obj.get("request", {})
    aud = obj.get("audit_data", {})

    uri = ""
    parts = req.get("request_line", "").split()
    if len(parts) > 1:
        uri = parts[1]

    ids = []
    for m in aud.get("messages", []):
        ids += [r for r in RULE_ID_RE.findall(m) if r not in SCORING_RULES]

    return {
        "log_time": tx.get("time", ""),
        "client_ip": tx.get("remote_address", ""),
        "client_port": tx.get("remote_port", ""),
        "uri": uri,
        "rule_ids": ",".join(dict.fromkeys(ids)),
    }

# ------------------------------------------------------------------ AI 판정 (배치)

def analyze_batch(log_block):
    """여러 로그를 한 프롬프트에 묶어 판정. results 배열을 반환."""
    payload = {
        "contents": [
            {"parts": [{"text": PROMPT.format(log_block=log_block)}]}
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0,
        },
    }
    data = json.dumps(payload).encode("utf-8")

    for attempt in range(config.API_RETRY + 1):
        try:
            req = urllib.request.Request(
                GEMINI_URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = resp.read().decode("utf-8")

            obj = json.loads(body)

            # 응답 구조: candidates[0].content.parts[*].text
            try:
                parts = obj["candidates"][0]["content"]["parts"]
                text = "".join(p.get("text", "") for p in parts)
                if not text:
                    raise KeyError("no text in parts")
            except (KeyError, IndexError):
                fb = obj.get("promptFeedback", {})
                print("  [경고] 응답에 결과 없음 (시도 " + str(attempt + 1) + "): " + str(fb),
                      file=sys.stderr)
                text = None

            if text:
                parsed = json.loads(text)
                # results 배열을 꺼냄 (형식이 어긋나면 None)
                if isinstance(parsed, dict) and isinstance(parsed.get("results"), list):
                    return parsed["results"]
                print("  [경고] results 배열 없음: " + text[:200], file=sys.stderr)
                return None

        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            print("  [경고] HTTP " + str(e.code) + " (시도 " + str(attempt + 1) + "): "
                  + err_body[:300], file=sys.stderr)
            # 429(레이트리밋)/5xx만 재시도, 그 외 4xx는 즉시 포기
            if e.code not in (429, 500, 503):
                return None
        except urllib.error.URLError as e:
            print("  [경고] 네트워크 오류 (시도 " + str(attempt + 1) + "): " + str(e.reason),
                  file=sys.stderr)
        except (TimeoutError, OSError) as e:
            # socket.timeout 등 연결/읽기 타임아웃
            print("  [경고] 타임아웃/연결 오류 (시도 " + str(attempt + 1) + "): " + str(e),
                  file=sys.stderr)
        except json.JSONDecodeError as e:
            print("  [경고] JSON 파싱 실패 (시도 " + str(attempt + 1) + "): " + str(e),
                  file=sys.stderr)

        if attempt < config.API_RETRY:
            wait = min((2 ** attempt) * config.API_SLEEP, 30)
            print("  ... " + format(wait, ".0f") + "초 대기 후 재시도", file=sys.stderr)
            time.sleep(wait)

    return None

# ------------------------------------------------------------------ 2차 검증 (Groq, 배치)

GROQ_VERIFY_PROMPT = """다음은 ModSecurity WAF 로그 여러 건과, 1차 AI가 내린 판정들이다.
각 항목은 "===== ITEM #N =====" 로 구분된다.
너는 2차 검증자다. 각 판정에 동의하는지 판단하라.

[판정 기준]
- matched data가 공격 구문으로 문법이 완결되면 true_positive(정탐)
- 자유 텍스트 필드에 우연히 든 키워드로 실제 공격이 아니면 false_positive(오탐)
- 애매하면 needs_review

[검증 대상 목록]
{item_block}

반드시 아래 JSON 형식으로만 응답하라.
"results" 배열에는 위 항목 각각에 대한 검증을 넣되,
"index"는 해당 항목 번호(ITEM #N 의 N)와 정확히 일치해야 한다.
항목이 5건이면 결과도 반드시 5건이어야 한다.

{{
  "results": [
    {{
      "index": 1,
      "agree": true 또는 false,
      "my_verdict": "true_positive | false_positive | needs_review",
      "comment": "동의/반대 사유를 1문장으로"
    }}
  ]
}}"""


def verify_batch_groq(items):
    """여러 (판정, 로그)를 한 번에 Groq으로 검증.
    items: [(result, log_text), ...]
    반환: index(1..N) -> {"agree", "my_verdict", "comment"} dict.
          호출 자체가 실패하면 None.
    """
    block_parts = []
    for n, (result, log_text) in enumerate(items, 1):
        block_parts.append(
            "===== ITEM #" + str(n) + " =====\n"
            + "[WAF 로그]\n" + log_text[:4000] + "\n"
            + "[1차 판정]\n"
            + "verdict: " + str(result.get("verdict")) + "\n"
            + "attack_name: " + str(result.get("attack_name")) + "\n"
            + "reason: " + str(result.get("reason"))
        )
    item_block = "\n\n".join(block_parts)

    payload = {
        "model": config.GROQ_MODEL,
        "messages": [{"role": "user",
                      "content": GROQ_VERIFY_PROMPT.format(item_block=item_block)}],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    data = json.dumps(payload).encode("utf-8")

    for attempt in range(config.API_RETRY + 1):
        try:
            req = urllib.request.Request(
                GROQ_URL,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + config.GROQ_API_KEY,
		    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = resp.read().decode("utf-8")

            obj = json.loads(body)
            text = obj["choices"][0]["message"]["content"]
            parsed = json.loads(text)

            results = parsed.get("results")
            if not isinstance(results, list):
                print("  [Groq경고] results 배열 없음", file=sys.stderr)
                return None

            by_index = {}
            for r in results:
                if isinstance(r, dict) and "index" in r:
                    try:
                        by_index[int(r["index"])] = r
                    except (TypeError, ValueError):
                        pass
            return by_index

        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            print("  [Groq경고] HTTP " + str(e.code) + " (시도 " + str(attempt + 1) + "): "
                  + err_body[:200], file=sys.stderr)
            if e.code not in (429, 500, 503):
                return None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print("  [Groq경고] 네트워크/타임아웃 (시도 " + str(attempt + 1) + "): " + str(e),
                  file=sys.stderr)
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            print("  [Groq경고] 응답 파싱 실패 (시도 " + str(attempt + 1) + "): " + str(e),
                  file=sys.stderr)
            return None

        if attempt < config.API_RETRY:
            time.sleep(min((2 ** attempt) * config.API_SLEEP, 30))

    return None

# ------------------------------------------------------------------ 검증

def validate_basic(result):
    """코드 검증 (건별) — verdict 값 검사 + confidence 임계값.
    Groq 검증 전에 먼저 적용한다. notes 리스트를 반환.
    """
    notes = []

    # 1. verdict 값이 유효한가
    if result.get("verdict") not in ("true_positive", "false_positive", "needs_review"):
        result["verdict"] = "needs_review"
        notes.append("verdict 값 비정상")

    # 2. 오탐 판정은 확신도가 높을 때만 인정
    #    (정탐을 오탐이라 부르는 것이 훨씬 위험하므로 여기만 문턱을 높인다)
    try:
        conf = float(result.get("confidence", 0))
    except (TypeError, ValueError):
        conf = 0.0
    result["confidence"] = conf

    if result["verdict"] == "false_positive" and conf < config.FP_CONFIDENCE_THRESHOLD:
        result["verdict"] = "needs_review"
        notes.append("오탐 확신도 부족 (" + format(conf, ".2f")
                     + " < " + str(config.FP_CONFIDENCE_THRESHOLD) + ")")

    return notes


def apply_groq_verdict(result, notes, groq_item):
    """Groq 검증 결과(groq_item)를 판정에 반영. groq_item이 None이면 검증 실패 처리."""
    if groq_item is None:
        # Groq 검증 실패 -> 1차 판정 유지 + 표시
        notes.append("2차 검증 실패 (Groq 응답 없음) - 1차 판정 유지")
        result["validation"] = " | ".join(notes) if notes else "OK"
        return result

    groq_verdict = groq_item.get("my_verdict")
    comment = groq_item.get("comment", "")
    agree = groq_item.get("agree")

    # 동의 여부 결정: agree 필드 우선, 없으면 verdict 일치로 판단
    if agree is True:
        is_agree = True
    elif agree is False:
        is_agree = False
    else:
        is_agree = (groq_verdict == result.get("verdict"))

    if is_agree:
        notes.append("2차 검증 통과 (Groq 동의)")
    else:
        prev = result["verdict"]
        result["verdict"] = "needs_review"
        notes.append("2차 검증 불일치 (1차: " + str(prev)
                     + " / Groq: " + str(groq_verdict) + ") -> 검토 필요")

    result["validation"] = " | ".join(notes) if notes else "OK"
    return result

# ------------------------------------------------------------------ 적재

def save(conn, tid, meta, result, raw_log):
    conn.execute("""
        INSERT OR IGNORE INTO analysis
        (transaction_id, log_time, client_ip, client_port, uri, rule_ids,
         verdict, confidence, attack_name, cwe_id, cwe_name,
         reason, evidence, validation, raw_log, analyzed_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        tid, meta["log_time"], meta["client_ip"], meta["client_port"],
        meta["uri"], meta["rule_ids"],
        result.get("verdict"), result.get("confidence"),
        result.get("attack_name"), result.get("cwe_id"), result.get("cwe_name"),
        result.get("reason"),
        json.dumps(result.get("evidence") or [], ensure_ascii=False),
        result.get("validation"),
        raw_log,                                  # 마스킹된 원본 전체 (재분석용)
        datetime.now().isoformat(timespec="seconds"),
    ))
    conn.commit()

# ------------------------------------------------------------------ 분석 실행

def run_analyze():
    conn = init_db()
    events = read_new_events(conn)

    if not events:
        print("새로 분석할 로그가 없습니다.")
        return

    total = len(events)
    bs = config.BATCH_SIZE
    print("신규 차단 로그 " + str(total) + "건 감지. "
          + str(bs) + "건씩 묶어 분석합니다.\n")

    ok = fail = 0

    # events 를 BATCH_SIZE 크기로 잘라 처리
    for start in range(0, total, bs):
        batch = events[start:start + bs]

        # 각 로그를 마스킹하고 번호를 붙여 하나의 블록으로 합침
        masked_list = []      # (tid, obj, meta, masked) 튜플 보관
        block_parts = []
        for n, (tid, obj, raw_line) in enumerate(batch, 1):
            masked = mask(raw_line)
            meta = extract_meta(obj)
            masked_list.append((tid, obj, meta, masked))
            block_parts.append("===== LOG #" + str(n) + " =====\n" + masked)

        log_block = "\n\n".join(block_parts)

        print("[배치 " + str(start // bs + 1) + "] "
              + str(len(batch)) + "건 전송 중...")

        results = analyze_batch(log_block)

        if results is None:
            print("  -> 배치 분석 실패. 다음 실행 때 재시도됩니다.\n")
            fail += len(batch)
            continue

        # index 기준으로 결과를 빠르게 찾도록 dict 화
        by_index = {}
        for r in results:
            if isinstance(r, dict) and "index" in r:
                try:
                    by_index[int(r["index"])] = r
                except (TypeError, ValueError):
                    pass

        # 1) 각 로그에 1차 판정을 짝짓고, 코드 검증(verdict/confidence)을 먼저 적용
        prepared = []   # (tid, meta, masked, result, notes)
        for n, (tid, obj, meta, masked) in enumerate(masked_list, 1):
            result = by_index.get(n)
            if result is None:
                # AI가 이 번호를 빠뜨림 -> 검토필요로 저장 (유실 방지)
                result = {
                    "verdict": "needs_review",
                    "confidence": 0.0,
                    "attack_name": None,
                    "cwe_id": None,
                    "cwe_name": None,
                    "reason": "AI 응답에 해당 로그 판정이 누락됨",
                    "evidence": [],
                }
            notes = validate_basic(result)   # 코드 검증 (건별)
            prepared.append((tid, meta, masked, result, notes))

        # 2) 이 배치 전체를 Groq으로 한 번에 2차 검증
        print("  [Groq 2차 검증] " + str(len(prepared)) + "건 전송 중...")
        groq_items = [(p[3], p[2]) for p in prepared]   # (result, masked)
        groq_by_index = verify_batch_groq(groq_items)   # None이면 배치 전체 실패

        # 3) Groq 결과를 각 판정에 반영하고 저장
        for n, (tid, meta, masked, result, notes) in enumerate(prepared, 1):
            if groq_by_index is None:
                groq_item = None                  # 배치 전체 실패
            else:
                groq_item = groq_by_index.get(n)  # 개별 누락이면 None -> 검증실패 처리
            result = apply_groq_verdict(result, notes, groq_item)
            save(conn, tid, meta, result, masked)

            mark = {"true_positive": "정탐",
                    "false_positive": "오탐",
                    "needs_review": "검토필요"}.get(result["verdict"], "?")
            print("  #" + str(n) + " " + meta["client_ip"] + " " + meta["uri"][:50])
            print("    -> " + mark + " (" + format(result["confidence"] * 100, ".0f") + "%) "
                  + str(result.get("attack_name")) + " / "
                  + (result.get("cwe_id") or "CWE 미상"))
            if result["validation"] != "OK":
                print("       검증: " + result["validation"])
            ok += 1

        print()
        time.sleep(config.API_SLEEP)

    print("분석 완료: 성공 " + str(ok) + "건 / 실패 " + str(fail) + "건")
    conn.close()

# ------------------------------------------------------------------ 리포트

LINE = "=" * 78
THIN = "-" * 78

def run_report(days=1):
    conn = init_db()
    since = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")

    rows = conn.execute("""
        SELECT verdict, confidence, attack_name, cwe_id, cwe_name,
               reason, evidence, validation, client_ip, client_port, uri, rule_ids, log_time
        FROM analysis WHERE analyzed_at >= ?
        ORDER BY
          CASE verdict WHEN 'false_positive' THEN 0
                       WHEN 'needs_review'   THEN 1
                       ELSE 2 END,
          confidence DESC
    """, (since,)).fetchall()

    print(LINE)
    print("  ModSecurity WAF AI 분석 리포트   "
          + format(datetime.now(), "%Y-%m-%d %H:%M")
          + "   (최근 " + str(days) + "일)")
    print(LINE)

    if not rows:
        print("\n해당 기간에 분석된 로그가 없습니다.\n")
        conn.close()
        return

    fp = [r for r in rows if r[0] == "false_positive"]
    nr = [r for r in rows if r[0] == "needs_review"]
    tp = [r for r in rows if r[0] == "true_positive"]

    print("\n  총 " + str(len(rows)) + "건   |   오탐 " + str(len(fp))
          + "   검토필요 " + str(len(nr)) + "   정탐 " + str(len(tp)))
    print("  오탐 비율: " + format(len(fp) / len(rows) * 100, ".1f") + "%")

    def block(title, items):
        if not items:
            return
        print("\n" + THIN)
        print("  [" + title + "]  " + str(len(items)) + "건")
        print(THIN)
        for r in items:
            (verdict, conf, attack, cwe_id, cwe_name,
             reason, evidence, validation, ip, port, uri, rules, ltime) = r
            print("\n  * " + (attack or "미분류")
                  + "   (확신도 " + format(conf * 100, ".0f") + "%)")
            print("    시각   : " + str(ltime))
            print("    출발지 : " + str(ip) + ":" + str(port))
            print("    경로   : " + str(uri))
            print("    룰 ID  : " + (rules or "-"))
            print("    CWE    : " + (cwe_id or "미상")
                  + ((" (" + cwe_name + ")") if cwe_name else ""))
            print("    근거   : " + str(reason))
            try:
                evs = json.loads(evidence or "[]")
            except json.JSONDecodeError:
                evs = []
            for e in evs:
                print("             - " + str(e))
            if validation and validation != "OK":
                print("    ※ 검증 : " + validation)

    block("오탐 후보 - 예외 규칙 검토 필요", fp)
    block("검토 필요 - 사람의 확인이 필요함", nr)

    # 정탐은 상세 대신 요약만
    if tp:
        print("\n" + THIN)
        print("  [정탐]  " + str(len(tp)) + "건")
        print(THIN)
        by_type = {}
        for r in tp:
            key = r[3] or r[2] or "미분류"       # cwe_id 우선
            by_type[key] = by_type.get(key, 0) + 1
        for k, v in sorted(by_type.items(), key=lambda x: -x[1]):
            print("    " + k.ljust(28) + " " + str(v) + "건")

        ips = {}
        for r in tp:
            ips[r[8]] = ips.get(r[8], 0) + 1
        top = sorted(ips.items(), key=lambda x: -x[1])[:5]
        if top:
            print("\n    상위 출발지 IP")
            for ip, c in top:
                print("      " + ip.ljust(20) + " " + str(c) + "건")

    # 2차 검증 미완료 (판정 무관하게, Groq 검증 실패한 건 전부)
    #    validation 컬럼(인덱스 7)에 "2차 검증 실패"가 들어간 건을 모음
    verdict_kr = {"true_positive": "정탐",
                  "false_positive": "오탐",
                  "needs_review": "검토필요"}
    unverified = [r for r in rows if r[7] and "2차 검증 실패" in r[7]]
    if unverified:
        print("\n" + THIN)
        print("  [2차 검증 미완료]  " + str(len(unverified)) + "건")
        print("  (Groq 검증을 받지 못함 - 1차 판정만 적용됨)")
        print(THIN)
        for r in unverified:
            v_kr = verdict_kr.get(r[0], "?")
            attack = r[2] or "미분류"
            ip = r[8]
            val = r[7]
            # "2차 검증 실패 (...)" 부분만 추출해 사유 표시
            reason_part = val.split("2차 검증 실패")[-1] if "2차 검증 실패" in val else ""
            print("    * [" + v_kr + "] " + attack + " (" + str(ip) + ")"
                  + reason_part)

    print("\n" + LINE + "\n")
    conn.close()

# ------------------------------------------------------------------ 진입점

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd == "analyze":
        run_analyze()
    elif cmd == "report":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        run_report(days)
    else:
        run_analyze()
        print()
        run_report()
