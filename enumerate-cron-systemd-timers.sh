#!/usr/bin/env bash
set -eu
ARG1=${ARG1:-}   
HOSTNAME=$(hostname)
AR_LOG="/var/ossec/active-response/active-responses.log"
TMP="/tmp/arlog.$$"; LOG_PATH="/tmp/enumerate-cron-timers.log"; LOG_MAX_KB=100; LOG_KEEP=5
rotate_log(){ [[ -f $LOG_PATH ]] || return; local kb=$(( $(stat -c%s "$LOG_PATH")/1024 )); if (( kb>=LOG_MAX_KB ));then for((i=LOG_KEEP-1;i>=0;i--));do [[ -f $LOG_PATH.$i ]]&&mv "$LOG_PATH.$i" "$LOG_PATH.$((i+1))";done; mv "$LOG_PATH" "$LOG_PATH.1";fi;}
log(){ printf '[%s][%s] %s\n' "$(date +'%F %T.%3N')" "$1" "$2" | tee -a "$LOG_PATH"; }
write_json(){ printf '%s' "$1" > "$TMP"; mv -f "$TMP" "$AR_LOG" 2>/dev/null || mv -f "$TMP" "${AR_LOG}.new"; }
rotate_log

cronsys=()

while IFS= read -r file; do
  cronsys+=("$(jq -n --arg type system_cron --arg file "$file" '{type:$type,file:$file}')")
done < <(grep -h -E -v '^(#|$)' /etc/cron*/* 2>/dev/null | awk '{print FILENAME":"$0}' | cut -d: -f1 | sort -u)


users=("$ARG1"); [[ -z $ARG1 ]] && users=($(awk -F: '{print $1}' /etc/passwd))
for u in "${users[@]}"; do
  crontab -l -u "$u" 2>/dev/null | grep -vE '^(#|$)' | while read -r line; do
    cronsys+=("$(jq -n --arg type user_cron --arg user "$u" --arg entry "$line" '{type:$type,user:$user,entry:$entry}')")
  done
done


timers=()
while read -r t; do
  timers+=("$(jq -n --arg type systemd_timer --arg timer "$t" '{type:$type,timer:$timer}')")
done < <(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $1}')

report=$(jq -n --arg host "$HOSTNAME" --arg ts "$(date -Iseconds)" \
  --argjson crons "[$(IFS=,;echo "${cronsys[*]}")]" \
  --argjson timers "[$(IFS=,;echo "${timers[*]}")]" \
  '{host:$host,timestamp:$ts,action:"enumerate_cron_systemd_timers",crons:$crons,timers:$timers}')

write_json "$report"
log INFO "Cron entries: ${#cronsys[@]}, timers: ${#timers[@]}"
exit 0
