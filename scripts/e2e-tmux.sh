#!/usr/bin/env bash
set -euo pipefail

if ! command -v tmux >/dev/null 2>&1; then
    echo 'just e2e requires tmux; install it before starting the matrix.' >&2
    exit 1
fi

session=kidobo-e2e
if tmux has-session -t "=${session}" 2>/dev/null; then
    echo "Session ${session} already exists; no new matrix was started." >&2
    echo "Attach with: tmux attach -t ${session}" >&2
    exit 1
fi

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
printf -v run_command '%q ' just --justfile "${repository}/Justfile" _e2e "$@"
printf -v pane_command '%s\n' \
    'tmux set-option -p remain-on-exit on' \
    "${run_command}" \
    'result=$?' \
    'printf "\njust e2e finished with exit status %s\n" "$result"' \
    'exit "$result"'

tmux new-session -d -s "${session}" -c "${repository}" bash -c "${pane_command}"
echo "Started just e2e in tmux session ${session}."
echo "Attach with: tmux attach -t ${session}"
echo 'Detach with Ctrl+b, then d; the matrix continues after SSH disconnects.'
