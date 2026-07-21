#!/usr/bin/env bash
# Creates the GitLab Release for a tag pipeline, run by the `release`
# job in .gitlab-ci.yml. Pulled out of the YAML (rather than an inline
# script: block) for the same reason as before -- readable JSON
# construction, not a giant one-liner.
#
# Posts directly to the GitLab Releases API (POST /projects/:id/releases)
# instead of shelling out to the release-cli tool. release-cli only
# ships as a Docker image, and jpps-linux-builder's primary executor is
# now shell, not Docker -- there's no other Docker-image-dependent step
# left in this pipeline, so it wasn't worth keeping just for this one
# job when the same result is a single curl POST.
#
# Expects: CHANGELOG.md and dist/*.deb, dist/*.rpm (from the package:*
# jobs' artifacts, pulled in via `needs:`) present in the working
# directory; python3 on PATH (for JSON construction -- safer than
# hand-escaping the changelog body into a shell string);
# CI_COMMIT_TAG/CI_API_V4_URL/CI_PROJECT_ID/CI_JOB_TOKEN set (standard
# GitLab CI predefined variables).

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

shopt -s nullglob
assets=(dist/*.deb dist/*.rpm)
shopt -u nullglob

if [ "${#assets[@]}" -eq 0 ]; then
    echo "error: no dist/*.deb or dist/*.rpm files found -- package jobs may have failed to produce artifacts" >&2
    exit 1
fi

echo "--- assets ---"
printf '%s\n' "${assets[@]}"

python3 - "${CI_COMMIT_TAG}" "${CI_API_V4_URL}" "${CI_PROJECT_ID}" "${assets[@]}" <<'PYEOF' > release-payload.json
import json
import sys

tag, api_url, project_id, *asset_paths = sys.argv[1:]
description = open("release-notes.md", encoding="utf-8").read()

payload = {
    "name": f"mlvpn {tag}",
    "tag_name": tag,
    "description": description,
    "assets": {
        "links": [
            {
                "name": path.split("/")[-1],
                "url": f"{api_url}/projects/{project_id}/packages/generic/mlvpn/{tag}/{path.split('/')[-1]}",
            }
            for path in asset_paths
        ]
    },
}
print(json.dumps(payload))
PYEOF

curl --fail --request POST \
    --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
    --header "Content-Type: application/json" \
    --data @release-payload.json \
    "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/releases"
