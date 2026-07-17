# conditional-deps-select

A minimal rules_go project whose `deps` attribute is a `select()`, used to make
the **`bazel query` vs `bazel cquery`** difference observable.

The dependency graph is:

```
//:app (go_binary)
  └─ embed //:app_lib (go_library)
       └─ deps = select({
              ":linux":  ["//platformlinux"],
              ":darwin": ["//platformdarwin"],
              "//conditions:default": [],
          })
```

No external Go modules are involved on purpose — the branch-selection mechanism
is identical whether a `select` branch points at a first-party `//target` or an
external `@repo//...` module, and keeping it first-party makes the fixture
deterministic (no `go.sum`, no module fetching).

## Why it exists

`bazel query` runs the loading phase only and, with the default
`--proto:flatten_selects`, returns **every** branch of a `select()`. `bazel
cquery` runs the analysis phase and returns only the branch matching the
resolved configuration. For dependency/vulnerability reporting that difference
is the crux: `query` **over-reports** deps from configurations you are not
scanning (e.g. a linux-only dependency surfacing in a darwin scan → a
false-positive vuln), whereas `cquery` reports only what is actually built for
the target's configuration.

## Reproduce

```sh
# Plain query flattens the select -> BOTH platform branches appear.
bazel query  "deps(//:app)" --output=label --noimplicit_deps | sort > /tmp/q.txt

# cquery resolves the select -> only the active configuration's branch appears
# (labels are annotated with a config hash; strip it for comparison).
bazel cquery "deps(//:app)" --output=label --noimplicit_deps \
  | sed -E 's/ \([^)]*\)$//' | sort > /tmp/cq.txt

# Labels present under query but dropped by cquery:
comm -23 /tmp/q.txt /tmp/cq.txt
```

On a darwin host this prints the linux branch that `cquery` correctly excludes:

```
//platformlinux:linux.go
//platformlinux:platformlinux
```

(On a linux host the symmetric result holds: `//platformdarwin:*` is dropped.)
