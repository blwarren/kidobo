#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: just publish-release [v]X.Y.Z

Prepares and validates a release in a temporary worktree, asks for confirmation,
then atomically pushes the release commit and tag, uploads locally built assets
with GitHub CLI, verifies the uploaded archive, and publishes the GitHub release.
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
required_commands=(gh cargo cat cmp date docker git grep head install just mkdir mktemp musl-gcc readelf rm rustup sed sha256sum sort tar uname)
for required_command in "${required_commands[@]}"; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        echo "missing required command: ${required_command}" >&2
        exit 1
    fi
done
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
    echo "publish-release requires a Linux x86_64 host" >&2
    exit 1
fi
if ! gh auth status --hostname github.com >/dev/null 2>&1; then
    echo "GitHub CLI is not authenticated for github.com; run: gh auth login" >&2
    exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"
origin_url="$(git config --get remote.origin.url)"
case "${origin_url}" in
    https://github.com/*)
        origin_repo="${origin_url#https://github.com/}"
        ;;
    git@github.com:*)
        origin_repo="${origin_url#git@github.com:}"
        ;;
    ssh://git@github.com/*)
        origin_repo="${origin_url#ssh://git@github.com/}"
        ;;
    *)
        echo "origin is not a supported GitHub repository URL: ${origin_url}" >&2
        exit 1
        ;;
esac
origin_repo="${origin_repo%.git}"
github_repo="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
if [[ "${github_repo,,}" != "${origin_repo,,}" ]]; then
    echo "GitHub CLI repository (${github_repo}) does not match origin (${origin_repo})" >&2
    exit 1
fi

original_branch="$(git branch --show-current)"
original_head="$(git rev-parse HEAD)"
switched_to_main=false
temporary_root=""
release_worktree=""
artifact_root="${repo_root}/target/release-artifacts/${release_tag}"
archive_root="kidobo-${release_tag}-linux-x86_64"
archive_name="${archive_root}.tar.gz"
archive_path="${artifact_root}/${archive_name}"
checksums_path="${artifact_root}/SHA256SUMS"
release_notes_copy="${artifact_root}/release-notes.md"
artifacts_created=false
tag_created=false
refs_pushed=false
release_published=false
is_prerelease=false
if [[ ! "${release_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    is_prerelease=true
fi

print_recovery() {
    echo >&2
    echo "Git refs for ${release_tag} were pushed, but its GitHub release was not confirmed published." >&2
    echo "Local recovery artifacts were retained at: ${artifact_root}" >&2
    echo "Check the release first: gh release view ${release_tag} --repo ${github_repo}" >&2
    echo "If no draft exists, create it with:" >&2
    printf '  gh release create %q %q %q --repo %q --draft --verify-tag --title %q --notes-file %q' \
        "${release_tag}" "${archive_path}" "${checksums_path}" "${github_repo}" \
        "${release_tag}" "${release_notes_copy}" >&2
    if [[ "${is_prerelease}" == true ]]; then
        printf ' --prerelease' >&2
    fi
    printf '\n' >&2
    echo "If a draft already exists, replace its assets with:" >&2
    printf '  gh release upload %q %q %q --repo %q --clobber\n' \
        "${release_tag}" "${archive_path}" "${checksums_path}" "${github_repo}" >&2
    recovery_dir="${artifact_root}/downloaded"
    echo "Then download and verify the draft assets:" >&2
    printf '  mkdir -p %q\n' "${recovery_dir}" >&2
    printf '  gh release download %q --repo %q --dir %q --clobber --pattern %q --pattern %q\n' \
        "${release_tag}" "${github_repo}" "${recovery_dir}" "${archive_name}" "SHA256SUMS" >&2
    printf '  cmp %q %q\n' "${checksums_path}" "${recovery_dir}/SHA256SUMS" >&2
    printf '  (cd %q && sha256sum --check SHA256SUMS)\n' "${recovery_dir}" >&2
    printf '  tar -tzf %q\n' "${recovery_dir}/${archive_name}" >&2
    recovery_extract="${recovery_dir}/extracted"
    printf '  mkdir -p %q\n' "${recovery_extract}" >&2
    printf '  tar -C %q -xzf %q\n' "${recovery_extract}" "${recovery_dir}/${archive_name}" >&2
    printf '  %q --version\n' "${recovery_extract}/${archive_root}/kidobo" >&2
    echo "After verification, publish the draft with:" >&2
    printf '  gh release edit %q --repo %q --draft=false' "${release_tag}" "${github_repo}" >&2
    if [[ "${is_prerelease}" == false ]]; then
        printf ' --latest' >&2
    fi
    printf '\n' >&2
}

cleanup() {
    status=$?
    trap - EXIT
    if [[ "${tag_created}" == true && "${refs_pushed}" == false ]]; then
        git -C "${repo_root}" tag --delete "${release_tag}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${release_worktree}" ]]; then
        git -C "${repo_root}" worktree remove --force "${release_worktree}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${temporary_root}" ]]; then
        rm -rf "${temporary_root}"
    fi
    if [[ "${artifacts_created}" == true && "${refs_pushed}" == false ]]; then
        rm -rf "${artifact_root}"
    fi
    if [[ "${switched_to_main}" == true && "${refs_pushed}" == false ]]; then
        if [[ -n "${original_branch}" ]]; then
            git -C "${repo_root}" switch --quiet "${original_branch}" >/dev/null 2>&1 || true
        else
            git -C "${repo_root}" switch --quiet --detach "${original_head}" >/dev/null 2>&1 || true
        fi
    fi
    if [[ "${refs_pushed}" == true && "${release_published}" == false ]]; then
        print_recovery
    fi
    exit "${status}"
}
trap cleanup EXIT

if [[ -n "$(git status --porcelain)" ]]; then
    echo "publish-release requires a clean worktree" >&2
    exit 1
fi
if [[ "$(git branch --show-current)" != "main" ]]; then
    echo "[release] switching to main"
    git switch main
    switched_to_main=true
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
if gh release view "${release_tag}" --repo "${github_repo}" >/dev/null 2>&1; then
    echo "GitHub release already exists: ${release_tag}" >&2
    exit 1
fi
if [[ -e "${artifact_root}" ]]; then
    echo "release artifact directory already exists: ${artifact_root}" >&2
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

echo "[release] installing pinned validation tools"
just _install-deny _install-audit _install-coverage

temporary_root="$(mktemp -d)"
release_worktree="${temporary_root}/worktree"

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

echo "[release] running local CI on the prepared candidate"
just ci
echo "[release] running release-only validation"
just release-notes-check
just coverage
just rustdoc
just exercise-release
just release-compat
git diff --check --cached
if ! git diff --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
    echo "validation produced uncommitted changes outside the staged release update" >&2
    git status --short >&2
    exit 1
fi

echo "[release] packaging locally built artifacts"
package_root="${temporary_root}/package/${archive_root}"
mkdir -p "${package_root}" "${artifact_root}"
artifacts_created=true
install -m 0755 target/x86_64-unknown-linux-musl/release/kidobo "${package_root}/kidobo"
install -m 0644 README.md LICENSE "${package_root}/"
tar -C "${temporary_root}/package" -czf "${archive_path}" "${archive_root}"
(
    cd "${artifact_root}"
    sha256sum "${archive_name}" > SHA256SUMS
)
install -m 0644 "${release_notes_path}" "${release_notes_copy}"

echo
echo "Release ${release_tag} is ready to publish:"
git --no-pager diff --cached --stat
echo
git --no-pager diff --cached
echo
echo "Artifacts:"
echo "  ${archive_path}"
echo "  ${checksums_path}"
cat "${checksums_path}"
echo
read -r -p "Commit, tag, push, verify, and publish ${release_tag}? [y/N] " confirmation
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
refs_pushed=true

git -C "${repo_root}" merge --ff-only "${release_commit}"

echo "[release] creating draft GitHub release"
release_create_args=(
    release create "${release_tag}" "${archive_path}" "${checksums_path}"
    --repo "${github_repo}"
    --draft
    --verify-tag
    --title "${release_tag}"
    --notes-file "${release_notes_copy}"
)
if [[ "${is_prerelease}" == true ]]; then
    release_create_args+=(--prerelease)
fi
gh "${release_create_args[@]}"

echo "[release] downloading and verifying draft assets"
verification_root="${temporary_root}/downloaded"
mkdir -p "${verification_root}"
gh release download "${release_tag}" \
    --repo "${github_repo}" \
    --dir "${verification_root}" \
    --pattern "${archive_name}" \
    --pattern SHA256SUMS
cmp "${checksums_path}" "${verification_root}/SHA256SUMS"
(
    cd "${verification_root}"
    sha256sum --check SHA256SUMS
)

expected_listing="${temporary_root}/expected-archive-listing"
actual_listing="${temporary_root}/actual-archive-listing"
printf '%s\n' \
    "${archive_root}/" \
    "${archive_root}/LICENSE" \
    "${archive_root}/README.md" \
    "${archive_root}/kidobo" \
    | LC_ALL=C sort > "${expected_listing}"
tar -tzf "${verification_root}/${archive_name}" | LC_ALL=C sort > "${actual_listing}"
if ! cmp "${expected_listing}" "${actual_listing}"; then
    echo "downloaded release archive has unexpected contents" >&2
    exit 1
fi

extracted_root="${verification_root}/extracted"
mkdir -p "${extracted_root}"
tar -C "${extracted_root}" -xzf "${verification_root}/${archive_name}"
downloaded_binary="${extracted_root}/${archive_root}/kidobo"
if [[ ! -x "${downloaded_binary}" ]]; then
    echo "downloaded release binary is not executable" >&2
    exit 1
fi
downloaded_version="$("${downloaded_binary}" --version)"
if [[ "${downloaded_version}" != "kidobo ${release_version}" ]]; then
    echo "downloaded release binary reported unexpected version: ${downloaded_version}" >&2
    exit 1
fi

echo "[release] publishing verified GitHub release"
release_edit_args=(release edit "${release_tag}" --repo "${github_repo}" --draft=false)
if [[ "${is_prerelease}" == false ]]; then
    release_edit_args+=(--latest)
fi
gh "${release_edit_args[@]}"
release_published=true

release_url="https://github.com/${github_repo}/releases/tag/${release_tag}"
if resolved_release_url="$(
    gh release view "${release_tag}" --repo "${github_repo}" --json url --jq '.url'
)" && [[ -n "${resolved_release_url}" ]]; then
    release_url="${resolved_release_url}"
fi
echo
echo "Published and verified ${release_tag}:"
echo "${release_url}"
