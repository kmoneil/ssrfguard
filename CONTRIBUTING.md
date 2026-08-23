# Contributing

Thanks for looking. This is a security library, so the bar for a change is higher than for most
packages of its size, and this file exists so that bar is written down rather than discovered in
review.

**If you have found a vulnerability, do not open an issue.** [`SECURITY.md`](SECURITY.md) has the
private channel and the response window.

## Getting set up

```sh
uv sync --frozen --all-extras
.venv/bin/pre-commit install
```

That is the whole of it. `--all-extras` matters: without httpx and requests installed, the adapter
suites skip rather than run, and a green suite that skipped the adapters has proven nothing about
the two seams this package exists to provide.

`.python-version` says 3.13, and `uv.lock` is resolved for it. **The supported floor is 3.10 and
that is a promise about `src/`, not about the toolchain** -- locking the development tools for the
floor would drag ruff, mypy and ty years backwards to serve a promise they are not part of. The
compatibility matrix builds its own environment per interpreter for exactly that reason.

If `uv` cannot write its cache, `UV_CACHE_DIR=.uv-cache` puts it in the repository instead. That is
a workaround for a locked-down machine, not a project requirement -- do not bake it into anything
committed.

## Running things

Every named way of running this project's proofs lives in one place:

```sh
python scripts/lanes.py            # print the table: every lane, what it checks, whether it gates
python scripts/lanes.py fast       # run one
python scripts/lanes.py --list     # names only
```

**Do not spell a lane's command out anywhere else.** Not in a shell alias you commit, not in a
Makefile, not in a new workflow step. Two spellings of "how this project runs its tests" is how one
of them ends up with different flags, and that is not hypothetical here: the pre-push hook once ran
pytest directly and therefore ran *without* the coverage floor the `fast` lane gates on, so a change
could pass locally and fail CI. It now invokes the runner like everything else.

This is also why there is no Makefile and should not be one. `scripts/lanes.py` already prints a
better table than a hand-written `help` target, it stays correct because `tests/test_lanes.py`
asserts that every lane it knows about appears in the CI workflow, and a second runner would be a
second place for a flag to drift. If you want `make test` muscle memory badly enough, generate the
targets from `--list` and add a test that the two agree -- do not hand-maintain them.

**The pre-push hook runs `fast`, and `fast` is not everything.** If you touched a seam, run
`adapters` and `rebind` before you push; if you touched the address table or its generator, run
`egress`, which regenerates from IANA and compares. CI runs all of them, but finding out here is
faster than finding out there.

## What a change needs

**A test that fails before it and passes after.** For anything that changes what gets refused, the
stronger form: check that the test actually reds when you revert the fix. A test that has never
failed is indistinguishable from one that cannot, which is the same argument this repository makes
about its own leak check.

**A changelog entry**, under `Unreleased`, saying what changed and *why* -- the existing entries are
the house style and they are longer than a one-liner on purpose.

**Comments that explain why, not what.** This codebase is unusually heavy on prose and that is
deliberate: a control whose reasoning nobody can reconstruct is a control that gets configured
around. If a line is the way it is because of something measured, say what was measured. If it
departs from a registry, a specification or a client's documented behaviour, say which and say why.

**Coverage is measured as branches**, with the floor at 99%. Statement coverage cannot see a branch
-- both lines of an `if` execute, only one edge between them does -- and the gap that motivated the
change was a documented client path no test had ever constructed while the report said 100%.

## Things a review will send back

- **A runtime dependency.** There are none and there will be none; that is the product, and it is
  enforced by a test against the built metadata and by a lane that installs the wheel alone into a
  clean interpreter. An optional adapter's client goes behind an extra.
- **An IP address reaching TLS as `server_hostname`.** It silently disables certificate hostname
  verification and trades an SSRF hole for a worse one. Both seams are shaped so that no line in
  them *could* do it, and a change that reintroduces the possibility is the single failure this
  project most wants not to ship.
- **A refusal that does not name what it refused and which rule refused it.** A refusal a user
  cannot act on gets configured around, and a control that gets configured around protects nothing.
  The suite pins whole messages rather than matching substrings, so expect to update them.
- **A behaviour that differs between the client surfaces and is not written down.** Genuine
  asymmetries exist and each one is a named entry with a test in the parity matrix. An unnamed one
  is a defect, and the matrix has both an httpx-versus-requests axis and a
  synchronous-versus-asynchronous one -- put it on whichever it belongs to.
- **A hand edit to `src/ssrfguard/_registry.py`.** It is generated; run
  `python scripts/refresh_registry.py` and read the diff, because a registry change is a change to
  what this package refuses and is reviewed as one.
- **A filter where a structural fix exists.** An allowlist rather than a deny pattern, a parsed
  address rather than a string comparison, a type that cannot hold the invalid state rather than a
  check that it does not.

## A note on scope

An address this package refuses that it should permit is as much a bug as the reverse -- a guard
with false positives gets removed, and a removed control protects nothing. Both are worth
reporting. Which one outranks the other, and why, is the first thing the design notes settle.
