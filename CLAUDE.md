# Working conventions for this repo

## Git commits and pushes

Whenever making a git commit (and especially before a push), always
write a descriptive commit message that summarizes the actual changes
-- not a generic placeholder. Compose the message from what was
actually changed in that commit (bug fixed, feature added, files
touched, why), the same level of detail used in `CHANGELOG.md` entries.
Do this every time, not just when explicitly asked in the moment.

Standard sequence: stage, commit with a real descriptive message, then
push. If a tag is being pushed too (a release), tag with an annotated
tag (`git tag -a`) and push both the branch and the tag.

## Publishing .deb builds to the shared apt repo

**Only for public or internal GitLab projects -- never private ones.**
The repo has no read-side access control (plain HTTP/HTTPS, no login),
so anything published there is effectively public to anyone with the
URL regardless of the source project's own GitLab visibility setting.
Publishing a private project's package there would defeat the purpose
of it being private.

There's a self-hosted apt repository shared across projects in the
`jpps` GitLab group: `172.16.61.177`, nginx on port 8082, public at
`https://repo.jpps.us` via cloudflared. Flat apt repo format (no
`dists/`/`pool/` hierarchy) -- two independent sub-repos, `stable` and
`testing`, each just `.deb` files alongside a `Packages`/`Packages.gz`
index. Built as an alternative to GitLab's native Debian package
registry, which has an unresolved authentication bug on this instance
(traced all the way through `Gitlab::Auth::AuthFinders` with no
exception ever logged -- see `.gitlab-ci.yml`'s own comments on
`.upload_debian_registry` for the full trace).

**As of 2026-08, the repo index is GPG-signed** (`InRelease` +
`Release.gpg`, generated automatically by `publish-to-apt-repo` on
every publish -- no CI-side change needed, this happens entirely on
the repo host). `[trusted=yes]` in any existing client instructions is
now stale and should be replaced with `signed-by=` pointing at
`https://repo.jpps.us/repo-signing-key.asc` -- see
`jpps/apt-repo-server`'s README for the exact, verified sources.list
syntax (the channel name belongs in the URI itself, e.g.
`https://repo.jpps.us/stable`, with a bare `/` as the Suites value --
`URIs: https://repo.jpps.us` + `Suites: stable/` looks equally
reasonable but silently breaks every package download while still
reporting `apt update` as successful, confirmed the hard way).
Signing changes nothing about the access-control point above: the key
proves integrity/authenticity, not who's allowed to read.

Publishing credential: `APT_REPO_SSH_KEY`, a **group-level** (jpps)
file-type CI/CD variable -- already available to every project under
the group, no per-project setup needed. Authenticates as a restricted
`apt-publish` user on the repo host, scoped to only `/srv/apt-repo`.

This project's own `.gitlab-ci.yml` (`.publish_to_apt_repo` and
`.beta_build_suffix` blocks) is the reference implementation --
retrofitted 2026-09-16 to the Stable/Beta terminology (was
`.testing_build_suffix`), matching `jpps/omnibridge`'s already-converted
pattern (see the `jpps_stable_beta_release_pattern` memory). Two
gotchas worth not re-discovering:
1. GitLab writes file-type CI/CD variables to disk at `0664` -- SSH
   refuses a key that permissive. Copy it to a job-local file and
   `chmod 600` before use, don't pass the variable's own path to
   `ssh`/`scp` directly.
2. Both `cargo-deb` and `cargo-generate-rpm` were found to leave stale
   output files from earlier cached CI runs sitting in `target/...` --
   `rm -f` the previous output immediately before each build, or a
   `dist/` glob can silently pick up more than one file.

Version-suffix convention for a Beta (non-clean-tag) build: `~betaN`
for `.deb` (dpkg's tilde sorts *before* nothing, Debian Policy 5.6.12),
`0.betaN` for `.rpm` (no tilde equivalent in rpmvercmp; a leading
`0.` on the Release field is the standard convention). `N` is derived
from the tag itself (`v0.7.3-beta6` -> `beta6`), not a pipeline
counter, so the package version always matches the tag that produced
it. This guarantees a real Stable release always supersedes a leftover
Beta build on a target system, never the reverse -- get it backwards
and a real release can look like a downgrade to apt/dnf. Only the
package-version suffix and user-facing label changed -- the
apt-repo-server's `testing` sub-repo itself is NOT renamed (shared
infrastructure other projects' `sources.list` files already point at).

The repo server itself (`jpps/apt-repo-server`) is packaged as an
installable `.deb` too, so the whole setup is reproducible on a fresh
host rather than a one-off manual configuration.
