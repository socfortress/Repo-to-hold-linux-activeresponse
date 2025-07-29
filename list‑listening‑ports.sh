#!/usr/bin/env bash
set -eu
ARG1=${ARG1:-}    
HOSTNAME=$(hostname)
AR_LOG="/var/ossec/active-response/active-responses.log"
TMP="/tmp/arlog.$$"
LOG_PATH="/tmp/list-listening-ports.log"
LOG_MAX_KB=100; LOG_KEEP=5

rotate_log(){
  [[ -f $LOG_PATH ]] || return
  local kb=$(( $(stat -c%s "$LOG_PATH")/1024 ))
  if (( kb >= LOG_MAX_KB )); then
    for ((i=LOG_KEEP-1;i>=0;i--)); do [[ -f $LOG_PATH.$i ]] && mv -f "$LOG_PATH.$i" "$LOG_PATH.$((i+1))"; done
    mv -f "$LOG_PATH" "$LOG_PATH.1"
  fi
}
log(){ printf '[%s][%s] %s\n' "$(date +'%F %T.%3N')" "$1" "$2" | tee -a "$LOG_PATH"; }
write_json(){
  printf '%s' "$1" > "$TMP"
  mv -f "$TMP" "$AR_LOG" 2>/dev/null || mv -f "$TMP" "${AR_LOG}.new"
}
rotate_log
IFS=',' read -ra STD <<< "${ARG1:-80,443,22,25,53,3306,5432}"
declare -A std; for p in "${STD[@]}"; do std[$p]=1; done

readarray -t CONN < <(ss -lntupH)
ports=(); flagged=()
for line in "${CONN[@]}"; do
  proto=$(awk '{print $1}'<<<"$line")
  local_addr=$(awk '{print $5}'<<<"$line")
  port=${local_addr##*:}
  pidexe=$(awk '{print $7}'<<<"$line"|tr -d '"')
  pid=${pidexe%%/*}; exe=${pidexe#*/}
  path=""
  [[ -n $pid && -e /proc/$pid/exe ]] && path=$(readlink -f /proc/$pid/exe || true)
  j=$(jq -n --arg protocol "$proto" --arg port "$port" --arg pid "$pid" --arg exe "$exe" --arg path "${path:-}" \
        '{protocol:$protocol,port:($port|tonumber),pid:($pid|tonumber),process:$exe,exe_path:$path}')
  ports+=("$j")
  [[ -z ${std[$port]+x} || $path =~ (/tmp|/var/tmp|\.cache) ]] && flagged+=("$j")
done

report=$(jq -n \
  --arg host "$HOSTNAME" \
  --arg timestamp "$(date -Iseconds)" \
  --argjson total "${#ports[@]}" \
  --argjson flagged "${#flagged[@]}" \
  --argjson all "[$(IFS=,; echo "${ports[*]}")]" \
  --argjson suspicious "[$(IFS=,; echo "${flagged[*]}")]" \
  '{host:$host,timestamp:$timestamp,action:"list_listening_ports",total_ports:$total,flagged_ports:$flagged,all_ports:$all,suspicious:$suspicious}')

write_json "$report"
log INFO "Ports scanned: ${#ports[@]}, flagged: ${#flagged[@]}"
exit 0
