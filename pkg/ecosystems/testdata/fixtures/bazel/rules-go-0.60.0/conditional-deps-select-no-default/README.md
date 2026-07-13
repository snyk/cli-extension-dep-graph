# conditional-deps-select-no-default

Reproduces the exact production failure. Two structurally **unrelated**
targets:

```
//:app                     (go_binary, no select(), no conditional deps)
//broken:dpkg_status_like  (filegroup, select() with no //conditions:default,
                            keyed on a constraint no host ever satisfies)
```

There is no dependency edge between them in either direction —
`dpkg_status_like` mirrors `rules_distroless`' actual `apt` `dpkg_status`
target: a select() that lives somewhere in the workspace, unrelated to any
particular `java_binary` or `go_binary` being resolved.

## Why the two targets must be unrelated

An earlier version of this fixture put the select() on the resolution
target's own `deps`. That's the wrong reproduction: it conflates two
different things —

1. Whether **discovering** targets (`kind('go_binary', //...)`) can fail due
   to a select() *anywhere* under `//...`, regardless of whether it's a
   dependency of anything being searched for.
2. Whether **resolving a target's own deps** (`deps(//:app)`) fails when that
   target's own select() doesn't match the host.

The original bug is (1). `bazel cquery` must configure every target matched
by a pattern like `//...` before it can filter by `kind()` — confirmed
empirically: `bazel cquery "kind('go_binary', //...)"` fails on
`//broken:dpkg_status_like` even though it is not a `go_binary` and nothing
depends on it. `bazel query` (loading phase only, never resolves selects)
is unaffected.

Because `//:app` has no select() of its own, `deps(//:app)` succeeds
regardless of host and never needs `--bazel-platforms` — that flag's purpose
(forcing a specific select() branch for a target's own deps) is covered by
the sibling `conditional-deps-select` fixture instead.

## Why the select is keyed on a custom constraint, not @platforms//os or //cpu

The real `dpkg_status` select() is keyed on actual `os`/`cpu` platform
constraints, which is what made the original bug host-dependent: it broke on
the client's macOS, but would resolve fine on a linux/amd64 *or* linux/arm64
host — because a host's auto-detected default platform satisfies whichever
branch matches its own OS/CPU.

That's a problem for a *regression test* specifically: this repo's CI runs
Bazel integration tests on `cimg/go`, which is linux/amd64. Verified
empirically (running the pre-fix code inside a real `cimg/go` container) that
an `@platforms//os`/`@platforms//cpu`-keyed select — even with no default —
resolves without error on that CI runner, exactly because linux/amd64 matches
one of the branches. A test built on that would pass under both the buggy and
fixed code in CI, giving zero actual regression coverage there.

So the select here is keyed on a custom `constraint_setting`
(`//broken:flavor`) that is never part of any platform's *default*
auto-detected constraint values — a host's default platform only ever sets
`@platforms//os` and `@platforms//cpu`, never a constraint_setting it doesn't
know about. Verified this stays unresolvable even with `--platforms`
explicitly set to a linux/amd64 platform. This makes the fixture fail
identically regardless of what OS/architecture actually runs the test.

## Reproduce

```sh
# Discovery: query never resolves selects, succeeds on any host, any target.
bazel query "kind('go_binary', //...)" --output=label      # -> //:app

# Discovery via cquery (the pre-fix code path) fails on the SAME query,
# purely because //broken:dpkg_status_like also lives under //... — on
# every host, regardless of OS/architecture:
bazel cquery "kind('go_binary', //...)" --output=label      # always fails

# //:app's own deps are completely unaffected either way:
bazel cquery "deps(//:app)" --output=label                  # always succeeds
```
