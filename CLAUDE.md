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
