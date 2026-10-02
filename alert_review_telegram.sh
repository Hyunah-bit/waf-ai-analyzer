#!/bin/bash
# =====================================================================
# WAF AI 검토 알림 - 텔레그램 전송 버전
#
# DB를 주기적으로 확인해서, 관리자가 봐야 할 판정
# (검토필요 needs_review / 오탐 false_positive)이 새로 생기면
# 그 건만 텔레그램으로 알림을 보낸다. 정탐(true_positive)은 무시.
#
# 파일 위치: /usr/local/bin/
#
# 사전 준비:
#   1) 텔레그램에서 @BotFather 로 봇 생성 -> 토큰 획득
#   2) 봇에게 아무 메시지나 보낸 뒤
#      https://api.telegram.org/bot<토큰>/getUpdates 열어 chat_id 확인
#   3) 아래 TG_TOKEN, TG_CHAT 에 입력
#
# 사용법:  sudo bash alert_review.sh
#   Ctrl+C 로 종료
# =====================================================================

# --- 텔레그램 설정 (본인 값으로 교체) ---
TG_TOKEN="여기에_봇_토큰_입력"      # 예: 1234567890:AAH...
TG_CHAT="여기에_chat_id_입력"       # 예: 987654321

# --- DB / 감시 주기 ---
DB="/usr/local/bin/waf_analysis.db"
INTERVAL=10                          # 몇 초마다 확인할지

# 이미 알림한 transaction_id를 기록 (중복 알림 방지)
SEEN_FILE="/tmp/waf_alert_seen.txt"
touch "$SEEN_FILE"

# --- 텔레그램 전송 함수 ---
send_telegram() {
    # $1 = 보낼 메시지 본문
    curl -s "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -d "chat_id=${TG_CHAT}" \
        --data-urlencode "text=$1" \
        >/dev/null 2>&1
}

echo "==================================================================="
echo " WAF AI 검토 알림 감시 시작 (텔레그램 전송)"
echo " 대상: 검토필요(needs_review) / 오탐(false_positive)"
echo " ${INTERVAL}초마다 확인합니다. (Ctrl+C 종료)"
echo "==================================================================="

# 시작 시 텔레그램 설정 간단 점검
if [ "$TG_TOKEN" = "여기에_봇_토큰_입력" ] || [ "$TG_CHAT" = "여기에_chat_id_입력" ]; then
    echo "[경고] TG_TOKEN / TG_CHAT 을 아직 설정하지 않았습니다."
    echo "       스크립트 상단을 본인 값으로 수정하세요."
fi

while true; do
    # 검토필요 + 오탐 건을 조회 (구분자 | 로 컬럼 분리)
    rows=$(sqlite3 -separator '|' "$DB" \
        "SELECT transaction_id, verdict, confidence, attack_name, cwe_id,
                client_ip, client_port, uri, reason
         FROM analysis
         WHERE verdict IN ('needs_review','false_positive')
         ORDER BY analyzed_at DESC")

    # 각 행을 확인
    while IFS='|' read -r tid verdict conf attack cwe ip port uri reason; do
        [ -z "$tid" ] && continue

        # 이미 알림한 건이면 건너뜀
        if grep -q "^$tid$" "$SEEN_FILE"; then
            continue
        fi

        # confidence(0~1)를 퍼센트로
        pct=$(awk "BEGIN{printf \"%.0f\", $conf*100}")

        # 판정 종류에 따라 머리말 결정
        if [ "$verdict" = "false_positive" ]; then
            head="[오탐 의심] WAF가 정상 요청을 차단했을 수 있습니다"
        else
            head="[검토 필요] 관리자의 확인이 필요합니다"
        fi

        # 텔레그램 메시지 본문 구성
        msg="🚨 WAF AI 검토 알림
${head}

판정   : ${verdict} (확신도 ${pct}%)
공격명 : ${attack:-미분류}
CWE    : ${cwe:-미상}
출발지 : ${ip}:${port}
경로   : ${uri}
근거   : ${reason}
시각   : $(date '+%Y-%m-%d %H:%M:%S')"

        # 텔레그램 전송
        send_telegram "$msg"
        echo "[전송] ${verdict} / ${attack:-미분류} -> 텔레그램 알림 발송 (${ip})"

        # 알림한 것으로 기록
        echo "$tid" >> "$SEEN_FILE"

    done <<< "$rows"

    sleep "$INTERVAL"
done
