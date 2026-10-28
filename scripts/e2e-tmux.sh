#!/usr/bin/env bash
set -euo pipefail

if ! command -v tmux >/dev/null 2>&1; then
    echo 'just e2e requires tmux; install it before starting the matrix.' >&2
    exit 1
fi

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
results="${KIDOBO_E2E_RESULTS_DIR:-${repository}/target/e2e}"
mkdir -p "$results"
results="$(cd "$results" && pwd -P)"
session=kidobo-e2e
if tmux has-session -t "=${session}" 2>/dev/null; then
    panes="$(tmux list-panes -s -t "=${session}" -F '#{pane_dead}')"
    if [[ "$(printf '%s\n' "$panes" | sort -u)" != 1 ]]; then
        echo "Session ${session} is active; no new matrix was started." >&2
        echo "Attach with: tmux attach -t ${session}" >&2
        exit 1
    fi
    # Upgrade recovery for sessions left behind by the old remain-on-exit policy.
    recovered="$(mktemp -d "${results}/recovered-session-XXXXXXXX")"
    pane_ids="$(tmux list-panes -s -t "=${session}" -F '#{pane_id}')"
    while IFS= read -r pane; do
        tmux capture-pane -p -t "$pane" -S - > "${recovered}/${pane}.log"
    done <<< "$pane_ids"
    tmux kill-session -t "=${session}"
    echo "Recovered completed session output: ${recovered}"
fi

log_directory="$(mktemp -d "${results}/launcher-XXXXXXXX")"
printf -v log_assignment 'log_directory=%q' "$log_directory"
printf -v run_command '%q ' just --justfile "${repository}/Justfile" _e2e "$@"
printf -v pane_command '%s\n' \
    "$log_assignment" \
    'trap '\''result=$?; printf "%s\n" "$result" > "$log_directory/exit-status"'\'' EXIT' \
    'tmux set-option -p remain-on-exit off || exit $?' \
    "${run_command} 2>&1 | tee \"\$log_directory/output.log\"" \
    'statuses=("${PIPESTATUS[@]}")' \
    'result=${statuses[0]}' \
    'if (( result == 0 )); then result=${statuses[1]}; fi' \
    'printf "\njust e2e finished with exit status %s\n" "$result" | tee -a "$log_directory/output.log"' \
    'exit "$result"'

tmux new-session -d -s "${session}" -c "${repository}" bash -c "${pane_command}"
echo "Started just e2e in tmux session ${session}."
echo "Attach with: tmux attach -t ${session}"
echo 'Detach with Ctrl+b, then d; the matrix continues after SSH disconnects.'
echo "Output and exit status: ${log_directory}"
echo 'The session closes automatically when the command finishes.'
