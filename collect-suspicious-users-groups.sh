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
AR_LOG_FALLBACK="${AR_LOG}.new"
TMP="/tmp/arlog.$$"
LOG_PATH="/tmp/collect-suspicious-users-groups.log"
LOG_MAX_KB=100
LOG_KEEP=5
run_start=$(date +%s)

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

log() {
  local level="$1"; shift
  local msg="$*"
  printf '[%s][%s] %s\n' "$(date +'%F %T.%3N')" "$level" "$msg" | tee -a "$LOG_PATH"
}

write_json() {
  printf '%s' "$1" > "$TMP"
  if mv -f "$TMP" "$AR_LOG" 2>/dev/null; then
    log INFO "JSON successfully written to $AR_LOG"
    echo "JSON written to $AR_LOG"
    return 0
  else
    mv -f "$TMP" "$AR_LOG_FALLBACK"
    log WARN "Log locked, wrote results to $AR_LOG_FALLBACK"
    echo "WARNING: $AR_LOG locked, JSON saved to $AR_LOG_FALLBACK"
    return 1
  fi
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
    log INFO "Flagged user: $user (uid=$uid, noexpiry=$noexpiry, locked=$locked)"
  fi
done <<< "$passwd"

sudoers=$(grep -h -vE '^(#|Defaults)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | tr -s ' ')
flagsudo=()
while read -r line; do
  [[ -z $line ]] && continue
  usr=$(awk '{print $1}' <<< "$line")
  flagsudo+=("$(jq -n --arg user "$usr" --arg entry "$line" '{user:$user,sudo_entry:$entry}')")
  log INFO "Flagged sudo anomaly for user: $usr (entry: $line)"
done <<< "$sudoers"

report=$(jq -n \
  --arg host "$HOSTNAME" \
  --arg ts "$(date -Iseconds)" \
  --argjson users "[$(IFS=,; echo "${sus_users[*]}")]" \
  --argjson sudo "[$(IFS=,; echo "${flagsudo[*]}")]" \
  --arg copilot_soar "true" \
  '{host:$host,timestamp:$ts,action:"collect_suspicious_users",flagged_users:$users,sudo_anomalies:$sudo,copilot_soar:($copilot_soar|test("true"))}')

# Show report on terminal
echo "===== JSON OUTPUT ====="
echo "$report"
echo "======================="

# Write JSON to the active-response log (overwrite)
if ! write_json "$report"; then
  log ERROR "Failed to write to $AR_LOG (log locked, used fallback)"
fi

log INFO "Flagged ${#sus_users[@]} suspicious users and ${#flagsudo[@]} sudo anomalies."
dur=$(( $(date +%s) - run_start ))
log INFO "=== SCRIPT END : duration ${dur}s ==="

exit 0
