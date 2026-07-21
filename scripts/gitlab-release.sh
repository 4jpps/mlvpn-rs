#!/usr/bin/env bash
# Creates the GitLab Release for a tag pipeline, run by the `release`
# job in .gitlab-ci.yml. Pulled out of the YAML (rather than an inline
# script: block) because building the dynamic --assets-link list needs
# a real bash array -- awkward to express safely as an inline one-liner
# without risking word-splitting/quoting bugs on filenames that vary
# per rpmbuild %{?dist} tag (fc41 today, fc42 next Fedora bump, etc.).
#
# Expects: CHANGELOG.md and dist/*.deb, dist/*.rpm (from the six
# package:* jobs' artifacts, pulled in via `needs:`) present in the
# working directory; release-cli on PATH (the release-cli image this
# job runs in); CI_COMMIT_TAG/CI_API_V4_URL/CI_PROJECT_ID/CI_JOB_TOKEN
# set (standard GitLab CI predefined variables).

set -euo pipefail

version="${CI_COMMIT_TAG#v}"

# Same idea as release.yml's python extraction: pull this version's own
# section out of CHANGELOG.md (between its `## [X.Y.Z]` heading and the
# next one), heading line stripped, so the Release body is the same
# human-written notes as the changelog rather than a raw commit list.
awk -v ver="$version" '
    /^## \[/ {
        if (found) exit
        if ($0 ~ ("\\[" ver "\\]")) { found = 1; next }
        next
    }
    found { print }
' CHANGELOG.md > release-notes.md

if [ ! -s release-notes.md ]; then
    echo "warning: no CHANGELOG.md section found for version ${version}; falling back to a placeholder release body" >&2
    echo "See CHANGELOG.md for details." > release-notes.md
fi

echo "--- release-notes.md ---"
cat release-notes.md

assets_link_args=()
for f in dist/*.deb dist/*.rpm; do
    [ -e "$f" ] || continue
    name="$(basename "$f")"
    url="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/mlvpn/${CI_COMMIT_TAG}/${name}"
    assets_link_args+=(--assets-link "{\"name\":\"${name}\",\"url\":\"${url}\"}")
done

if [ "${#assets_link_args[@]}" -eq 0 ]; then
    echo "error: no dist/*.deb or dist/*.rpm files found -- package jobs may have failed to produce artifacts" >&2
    exit 1
fi

release-cli create \
    --name "mlvpn ${CI_COMMIT_TAG}" \
    --tag-name "${CI_COMMIT_TAG}" \
    --description "$(cat release-notes.md)" \
    "${assets_link_args[@]}"
