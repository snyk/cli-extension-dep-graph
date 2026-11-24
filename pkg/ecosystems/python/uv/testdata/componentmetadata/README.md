# Recorded uv exports for component metadata

Each file is the output of
`uv export --format cyclonedx1.5 --preview --locked --no-dev`, re-serialized
without whitespace to keep it small. Nothing else is changed.

| File | uv | Project |
|------|----|---------|
| `extras-0.12.22.json` | 0.12.22 | `requests[socks]==2.32.3`, an optional `rich` extra and a `dev` group |
| `extras-0.12.4.json` | 0.12.4 | the same lockfile; uv before 0.12.5 lists no distributions |
| `workspace-all-packages-0.12.22.json` | 0.12.22 | `--all-packages` on a virtual-root workspace: `member-a` (`pyyaml==6.0.2`, `idna==3.10`, a path dependency `local-dep`) and `member-b` (`member-a`, `six==1.16.0`) |

From uv 0.12.5, each component lists one `distribution` external reference per
sdist and wheel, each with its SHA-256. Component-level `hashes` stay empty.
Workspace members and path, git, directory and editable sources list none.
