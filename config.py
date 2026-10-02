# -*- coding: utf-8 -*-
"""
waf_ai 설정 파일

이 파일에는 자주 바뀌는 값과 민감한 값(API 키)만 둔다.
로직은 waf_ai.py 에 있고, 프롬프트는 prompt.txt 에 있다.

주의: 이 파일에 API 키가 들어가므로, git 에 올릴 경우
      .gitignore 에 config.py 를 반드시 추가할 것.

파일 위치: /usr/local/bin/
"""

# --- Gemini API (1차 판정) ---
GEMINI_API_KEY = "YOUR_API_KEY"     # <- 본인 키로 교체
MODEL = "gemini-3.1-flash-lite"

# --- Groq API (2차 검증) ---
GROQ_API_KEY = "YOUR_API_KEY"       # <- Groq 콘솔에서 발급
GROQ_MODEL = "openai/gpt-oss-120b"

# --- 파일 경로 ---
LOG_FILE_PATH = "/var/log/apache2/modsec_audit.log"
DB_PATH = "waf_analysis.db"

# --- 판정 파라미터 ---
FP_CONFIDENCE_THRESHOLD = 0.85   # 오탐 판정 최소 확신도

# --- API 호출 ---
API_RETRY = 4                    # 503(과부하) 대응을 위해 재시도 횟수 늘림
API_SLEEP = 60.0                  # 재시도 대기 계수(초). 실패 시 2,4,8,16초로 증가
BATCH_SIZE = 3                   # 로그 몇 건을 한 번의 API 호출로 판정할지
