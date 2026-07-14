#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: just publish-release [v]X.Y.Z

Prepares and validates a release in a temporary worktree, asks for confirmation,
then creates the release commit and annotated tag and atomically pushes both.
EOF
}

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
fi

requested_version="$1"
if [[ ! "${requested_version}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    echo "invalid release version: ${requested_version} (expected X.Y.Z or vX.Y.Z)" >&2
    exit 2
fi

release_tag="v${requested_version#v}"
release_version="${release_tag#v}"
repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

if [[ -n "$(git status --porcelain)" ]]; then
    echo "publish-release requires a clean worktree" >&2
    exit 1
fi
if [[ "$(git branch --show-current)" != "main" ]]; then
    echo "[release] switching to main"
    git switch main
fi

echo "[release] refreshing origin/main and tags"
git fetch --quiet origin main --tags
base_commit="$(git rev-parse HEAD)"
remote_main="$(git rev-parse refs/remotes/origin/main)"
if ! git merge-base --is-ancestor "${remote_main}" "${base_commit}"; then
    echo "local main must not be behind or diverged from origin/main before publishing" >&2
    exit 1
fi
if git rev-parse --verify --quiet "refs/tags/${release_tag}" >/dev/null; then
    echo "local tag already exists: ${release_tag}" >&2
    exit 1
fi
if [[ -n "$(git ls-remote --tags origin "refs/tags/${release_tag}")" ]]; then
    echo "remote tag already exists: ${release_tag}" >&2
    exit 1
fi

current_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
if [[ -z "${current_version}" ]]; then
    echo "unable to read the package version from Cargo.toml" >&2
    exit 1
fi
if [[ "${current_version}" == "${release_version}" ]]; then
    echo "Cargo.toml is already at ${release_version}" >&2
    exit 1
fi
if [[ ! -s release-notes/unreleased.md ]]; then
    echo "release-notes/unreleased.md is empty; refusing to publish an empty release" >&2
    exit 1
fi

temporary_root="$(mktemp -d)"
release_worktree="${temporary_root}/worktree"
tag_created=false
published=false

cleanup() {
    status=$?
    trap - EXIT
    if [[ "${tag_created}" == true && "${published}" == false ]]; then
        git tag --delete "${release_tag}" >/dev/null 2>&1 || true
    fi
    git worktree remove --force "${release_worktree}" >/dev/null 2>&1 || true
    rm -rf "${temporary_root}"
    exit "${status}"
}
trap cleanup EXIT

echo "[release] preparing ${release_tag} in a temporary worktree"
git worktree add --quiet --detach "${release_worktree}" "${base_commit}"
cd "${release_worktree}"

sed -i "0,/^version = \"${current_version}\"$/s//version = \"${release_version}\"/" Cargo.toml
echo "[release] updating Cargo.lock"
cargo update --package kidobo --precise "${release_version}"

readme_old="--version v${current_version}"
readme_new="--version ${release_tag}"
if ! grep -Fq -- "${readme_old}" README.md; then
    echo "README.md does not contain the expected installer version ${readme_old}" >&2
    exit 1
fi
sed -i "s/${readme_old}/${readme_new}/g" README.md

release_notes_path="release-notes/${release_tag}.md"
if [[ -e "${release_notes_path}" ]]; then
    echo "release notes already exist: ${release_notes_path}" >&2
    exit 1
fi
{
    printf '# Release %s\n\n' "${release_tag}"
    cat release-notes/unreleased.md
} > "${release_notes_path}"
: > release-notes/unreleased.md

release_date="$(date -u +%F)"
if grep -Eq "^${release_tag}[[:space:]]" release-notes/dates.tsv; then
    echo "release date already exists for ${release_tag}" >&2
    exit 1
fi
printf '%s %s\n' "${release_tag}" "${release_date}" >> release-notes/dates.tsv

echo "[release] regenerating release notes and changelog"
just _release-notes-format _release-notes-generate
git add Cargo.toml Cargo.lock README.md CHANGELOG.md release-notes
just release-notes-check

echo "[release] running release quality gates"
just _install-deny _install-audit ci
git diff --check --cached
if ! git diff --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
    echo "validation produced uncommitted changes outside the staged release update" >&2
    git status --short >&2
    exit 1
fi

echo
echo "Release ${release_tag} is ready to publish:"
git --no-pager diff --cached --stat
echo
git --no-pager diff --cached
echo
read -r -p "Commit, tag, and atomically push ${release_tag}? [y/N] " confirmation
if [[ ! "${confirmation}" =~ ^[Yy]$ ]]; then
    echo "release publication cancelled; the main worktree was not changed"
    exit 0
fi

git commit -m "Prepare ${release_tag} release"
release_commit="$(git rev-parse HEAD)"
git tag -a "${release_tag}" -m "Release ${release_tag}"
tag_created=true

if [[ "$(git -C "${repo_root}" branch --show-current)" != "main" ]] \
    || [[ "$(git -C "${repo_root}" rev-parse HEAD)" != "${base_commit}" ]] \
    || [[ -n "$(git -C "${repo_root}" status --porcelain)" ]]; then
    echo "the original main worktree changed during validation; publication cancelled" >&2
    exit 1
fi

echo "[release] confirming origin/main has not changed"
git fetch --quiet origin main
if [[ "$(git rev-parse refs/remotes/origin/main)" != "${remote_main}" ]]; then
    echo "origin/main changed during release validation; publication cancelled" >&2
    exit 1
fi

echo "[release] atomically pushing main and ${release_tag}"
git push --atomic origin \
    "${release_commit}:refs/heads/main" \
    "refs/tags/${release_tag}:refs/tags/${release_tag}"
published=true

git -C "${repo_root}" merge --ff-only "${release_commit}"
echo
echo "Published ${release_tag}. Monitor the release workflow at:"
echo "https://github.com/blwarren/kidobo/actions/workflows/release.yml"
