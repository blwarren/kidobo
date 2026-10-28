fixture_curl() {
  curl --noproxy '*' --connect-timeout 1 --max-time 1 "$@"
}

serve_dir() {
  local directory=$1 port=$2 label=$3 deadline=$((SECONDS + 5))
  if [[ -s "$directory/SHA256SUMS" ]] && cmp -s "$directory/SHA256SUMS" <(fixture_curl -fsS "http://127.0.0.1:$port/SHA256SUMS" 2>/dev/null); then return 0; fi
  python3 -m http.server --bind 127.0.0.1 --directory "$directory" "$port" >"$STATE/http-$label.log" 2>&1 9>&- &
  printf '%s\n' "$!" > "$STATE/http-$label.pid"
  while (( SECONDS < deadline )); do
    if fixture_curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  fail "HTTP fixture failed to start: $label"
}

start_source_fixture() {
  local deadline=$((SECONDS + 5))
  mkdir -p "$ROOT/fixtures"
  cat > "$ROOT/fixtures/feed.txt" <<EOF
198.51.100.44
2001:db8::44
EOF
  if cmp -s "$ROOT/fixtures/feed.txt" <(fixture_curl -fsS "http://127.0.0.1:$SOURCE_PORT/feed.txt" 2>/dev/null); then return 0; fi
  stop_fixture "$STATE/http-source.pid" "$ROOT/traffic.py source $ROOT/fixtures/feed.txt $SOURCE_PORT"
  python3 "$ROOT/traffic.py" source "$ROOT/fixtures/feed.txt" "$SOURCE_PORT" >"$STATE/http-source.log" 2>&1 9>&- &
  printf '%s\n' "$!" > "$STATE/http-source.pid"
  while (( SECONDS < deadline )); do
    if fixture_curl -fsS "http://127.0.0.1:$SOURCE_PORT/feed.txt" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  fail 'HTTP source fixture failed to start'
}

stop_fixture() {
  local pid_file=$1 expected=$2
  if [[ -s "$pid_file" ]]; then
    local pid
    pid=$(<"$pid_file")
    if [[ -r "/proc/$pid/cmdline" ]] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq -- "$expected"; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
    rm -f "$pid_file"
  fi
}

start_traffic_servers() {
  local address label pid_file ready_file log_file pid proc_state rc
  for address in "$V4_HOST" "$V6_HOST"; do
    if [[ "$address" == *:* ]]; then label=v6; else label=v4; fi
    pid_file="$STATE/server-$label.pid"
    ready_file="$STATE/server-$label.ready"
    log_file="$STATE/server-$label.log"
    stop_fixture "$pid_file" "$ROOT/traffic.py serve $address $TRAFFIC_PORT"
    rm -f "$ready_file"
    python3 "$ROOT/traffic.py" serve "$address" "$TRAFFIC_PORT" "$ready_file" >"$log_file" 2>&1 9>&- &
    pid=$!
    printf '%s\n' "$pid" > "$pid_file"
    for _ in {1..200}; do
      if [[ -s "$ready_file" ]]; then
        if [[ -r "/proc/$pid/cmdline" ]] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq -- "$ROOT/traffic.py serve $address $TRAFFIC_PORT"; then
          break
        fi
        fail "traffic fixture $label published readiness without a live matching process; log: $log_file"
      fi
      if [[ -r "/proc/$pid/stat" ]]; then
        proc_state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null) || proc_state=''
        if [[ "$proc_state" == Z || -z "$proc_state" ]]; then
          rc=0
          wait "$pid" || rc=$?
          fail "traffic fixture $label exited before readiness (status=$rc); log: $log_file; $(tail -n 20 "$log_file" 2>/dev/null || true)"
        fi
      else
        rc=0
        wait "$pid" || rc=$?
        fail "traffic fixture $label exited before readiness (status=$rc); log: $log_file; $(tail -n 20 "$log_file" 2>/dev/null || true)"
      fi
      sleep 0.05
    done
    [[ -s "$ready_file" ]] || fail "traffic fixture $label did not become ready within 10 seconds; log: $log_file; $(tail -n 20 "$log_file" 2>/dev/null || true)"
  done
}

start_irr_fixture() {
  local deadline=$((SECONDS + 5)) real_bgpq4
  real_bgpq4=$(command -v bgpq4) || fail 'packaged bgpq4 is unavailable'
  "$real_bgpq4" -v > "$STATE/bgpq4-version.txt" 2>&1
  mkdir -p "$ROOT/asn-bin"
  printf '#!/usr/bin/env bash\nexec %q -h 127.0.0.1:%q "$@"\n' "$real_bgpq4" "$IRR_PORT" > "$ROOT/asn-bin/bgpq4"
  chmod 0755 "$ROOT/asn-bin/bgpq4"
  stop_fixture "$STATE/irr.pid" "$ROOT/traffic.py irr $IRR_PORT"
  rm -f "$STATE/irr.ready" "$STATE/irr.error"
  : > "$STATE/irr-protocol.log"
  python3 "$ROOT/traffic.py" irr "$IRR_PORT" "$STATE/irr.ready" "$STATE/irr-protocol.log" "$STATE/irr.error" > "$STATE/irr.log" 2>&1 9>&- &
  printf '%s\n' "$!" > "$STATE/irr.pid"
  while (( SECONDS < deadline )); do
    [[ ! -s "$STATE/irr.error" ]] || fail 'IRR fixture rejected an unexpected request'
    [[ ! -s "$STATE/irr.ready" ]] || return 0
    sleep 0.05
  done
  fail 'IRR fixture did not become ready'
}
