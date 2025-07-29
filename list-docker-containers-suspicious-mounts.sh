#!/usr/bin/env bash
set -eu
HOSTNAME=$(hostname)
AR_LOG="/var/ossec/active-response/active-responses.log"; TMP="/tmp/arlog.$$"
LOG_PATH="/tmp/list-docker-containers.log"; LOG_MAX_KB=100; LOG_KEEP=5
rotate_log(){ [[ -f $LOG_PATH ]]||return; local kb=$(( $(stat -c%s "$LOG_PATH")/1024 )); if (( kb>=LOG_MAX_KB ));then for((i=LOG_KEEP-1;i>=0;i--));do [[ -f $LOG_PATH.$i ]]&&mv "$LOG_PATH.$i" "$LOG_PATH.$((i+1))";done; mv "$LOG_PATH" "$LOG_PATH.1";fi;}
log(){ printf '[%s][%s] %s\n' "$(date +'%F %T.%3N')" "$1" "$2" | tee -a "$LOG_PATH"; }
write_json(){ printf '%s' "$1" > "$TMP"; mv -f "$TMP" "$AR_LOG" 2>/dev/null || mv -f "$TMP" "${AR_LOG}.new"; }
rotate_log

containers=($(docker ps --format '{{.ID}}' 2>/dev/null || true))
full=(); flagged=()
for cid in "${containers[@]}"; do
  inspect=$(docker inspect "$cid" 2>/dev/null)
  mounts=$(echo "$inspect" | jq -r '.[0].Mounts[]? | "\(.Source):\(.Destination)"')
  name=$(echo "$inspect" | jq -r '.[0].Name')
  img=$(echo "$inspect" | jq -r '.[0].Config.Image')
  obj=$(jq -n --arg id "$cid" --arg name "$name" --arg img "$img" --arg mounts "$mounts" '{id:$id,name:$name,image:$img,mounts:($mounts|split("\n"))}')
  full+=("$obj")
  while read -r m; do [[ $m =~ ^/host_root|/var/run/docker.sock ]] && flagged+=("$obj") && break; done <<< "$mounts"
done

report=$(jq -n --arg host "$HOSTNAME" --arg ts "$(date -Iseconds)" \
 --argjson total "${#full[@]}" --argjson flagged "${#flagged[@]}" \
 --argjson all "[$(IFS=,;echo "${full[*]}")]" --argjson suspicious "[$(IFS=,;echo "${flagged[*]}")]" \
 '{host:$host,timestamp:$ts,action:"list_docker_containers",total_containers:$total,flagged:$flagged,containers:$all,suspicious:$suspicious}')

write_json "$report"
log INFO "Containers: ${#full[@]}, flagged: ${#flagged[@]}"
exit 0
