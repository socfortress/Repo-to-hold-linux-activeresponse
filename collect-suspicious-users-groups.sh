#!/usr/bin/env bash
set -eu

ARG1=${ARG1:-}         
ARG2=${ARG2:-}
ARG3=${ARG3:-}
ARG4=${ARG4:-}
ARG5=${ARG5:-}
ARG6=${ARG6:-}
HOSTNAME=$(hostname)
AR_LOG="/var/ossec/active-response/active-responses.log"
TMP="/tmp/arlog.$$"
LOG_PATH="/tmp/collect-suspicious-users.log"
LOG_MAX_KB=100
LOG_KEEP=5

rotate_log() {
  [[ -f $LOG_PATH ]] || return
  local kb=$(( $(stat -c%s "$LOG_PATH") / 1024 ))
  if (( kb >= LOG_MAX_KB )); then
    for ((i=LOG_KEEP-1; i>=0; i--)); do
      [[ -f $LOG_PATH.$i ]] && mv -f "$LOG_PATH.$i" "$LOG_PATH.$((i+1))"
    done
    mv -f "$LOG_PATH" "$LOG_PATH.1"
  fi
}

log() { printf '[%s][%s] %s\n' "$(date +'%F %T.%3N')" "$1" "$2" | tee -a "$LOG_PATH"; }

write_json() {
  printf '%s' "$1" > "$TMP"
  mv -f "$TMP" "$AR_LOG" 2>/dev/null || {
    mv -f "$TMP" "${AR_LOG}.new"
    log WARN "AR log locked, wrote fallback ${AR_LOG}.new"
  }
}

rotate_log
log INFO "=== SCRIPT START : Collect Suspicious Users & Groups ==="
regex="${ARG1:-'^.*$'}"
passwd=$(</etc/passwd)
shadow=$(sudo cat /etc/shadow 2>/dev/null || true)

sus_users=()
while IFS=: read -r user _ uid gid desc home shell; do
  [[ $user =~ $regex ]] || continue
  [[ $uid -lt 1000 ]] && continue  

  pwinfo=$(grep "^$user:" <<< "$shadow" || true)
  noexpiry=false; locked=false
  [[ $pwinfo =~ :: ]] && noexpiry=true
  [[ $pwinfo =~ \! ]] && locked=true

  if $noexpiry || ! $locked; then
    sus_users+=("$(jq -n \
      --arg u "$user" --arg uid "$uid" --arg home "$home" --arg shell "$shell" \
      --arg noexp "$noexpiry" --arg locked "$locked" \
      '{user:$u,uid:($uid|tonumber),home:$home,shell:$shell,password_never_expires:($noexp=="true"),account_locked:($locked=="true")}')")
  fi
done <<< "$passwd"
sudoers=$(grep -h -vE '^(#|Defaults)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | tr -s ' ')
flagsudo=()
while read -r line; do
  [[ -z $line ]] && continue
  usr=$(awk '{print $1}' <<< "$line")
  flagsudo+=("$(jq -n --arg user "$usr" --arg entry "$line" '{user:$user,sudo_entry:$entry}')")
done <<< "$sudoers"
report=$(jq -n \
  --arg host "$HOSTNAME" \
  --arg ts "$(date -Iseconds)" \
  --argjson users "[$(IFS=,; echo "${sus_users[*]}")]" \
  --argjson sudo "[$(IFS=,; echo "${flagsudo[*]}")]" \
  '{host:$host,timestamp:$ts,action:"collect_suspicious_users",flagged_users:$users,sudo_anomalies:$sudo}')

write_json "$report"
log INFO "Flagged users: ${#sus_users[@]}, sudo anomalies: ${#flagsudo[@]}"
log INFO "=== SCRIPT END ==="
exit 0
