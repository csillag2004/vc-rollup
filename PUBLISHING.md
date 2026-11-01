# Publishing checklist

Copy this file to `PUBLISHING.md` at the repository root when you start preparing the Zenodo
release. From then on, the `hygiene` workflow runs the publication gate (`just hygiene --publish`),
which checks everything a script can check. The items below are the rest. Tick each one and
write the evidence after it: a commit, a file and line, a command and its output, or a link. An
advisor signs the list off by approving the pull request that completes it. `.gitattributes`
keeps this file out of the Zenodo archive.

Filled in on 2026-11-01 against the head of the pull request that adds this file. An unticked
item says what is missing.

## Results

- [ ] `just reproduce` regenerates every figure and table in the paper, and `just reproduce --smoke`
      finishes in minutes. Evidence: the paper's evaluation chapter has no numbered figures or
      tables yet, so this cannot be ticked. What exists: a full `just reproduce` ran on 2026-10-31
      in 118 s and succeeded (`results/local/provenance.json`: `"success": true`,
      `"elapsedSeconds": 118.267`, revision `a2d0cf2`). CI runs `just reproduce --smoke` natively
      (`.github/workflows/test.yml:33`) and in the container (`test.yml:62`); both passed on the
      previous cleanup PR. Tick once the chapter exists and each of its figures and tables is in
      the results map.
- [ ] Recipes are named after their outputs, such as `fig-scalability` or `tab-robustness`. Evidence:
      the recipes are named after evaluation questions (`evaluate`, `benchmark`, `robustness`,
      `demo`; `justfile`), because the paper has no figure or table numbers to name them after.
      Rename or alias them when the evaluation chapter is written.
- [ ] The results map has one row per figure and table of the paper, each with its command,
      output path and time on the stated hardware. Evidence: `README.md`, section "Results map",
      has one row per result with recipe and output, and the total time of a full run (118 s) on
      the recorded hardware. It has no per-row times and no paper numbers, for the reason above.
- [ ] Every dependency is pinned in the `Dockerfile` and the lockfiles. Evidence: base images are
      pinned to exact version tags (`Dockerfile:1-3`: `rust:1.94.1-bookworm`,
      `foundry:v1.8.6`, `node:26.7.0-bookworm`), `just` to 1.58.0 with `--locked`
      (`Dockerfile:10`), npm by `offchain/package-lock.json` with `npm ci` (`Dockerfile:15`),
      Rust by `qlc/Cargo.lock` and `rust-toolchain.toml`, Python plotting by
      `scripts/evaluation-requirements.txt` (exact `==` versions), Lean by
      `verification/lean/lean-toolchain` and the checksum in `scripts/setup-toolchain.sh`. Not
      pinned: the Debian packages `zstd python3 python3-venv` (`Dockerfile:9`) and the base images
      by digest. Martin decides whether tags are enough.

## Metadata

- [x] The license was agreed with the advisors: Apache 2.0 for a tool, MIT otherwise. Evidence:
      MIT, Martin's ruling of 2026-10-31 in the cleanup session; `LICENSE:1` is `MIT License`,
      `.zenodo.json` and `CITATION.cff` say `MIT`.
- [x] `related_identifiers` in `.zenodo.json` lists `isDerivedFrom` for a fork's upstream and
      `isSupplementTo` for each paper with a DOI, and nothing else. Evidence: the field is absent.
      The paper has no DOI or public URL yet, and the repository is not a fork. The entry it had
      pointed the repository at itself and was removed. Add `isSupplementTo` when the paper has a
      public identifier.
- [x] A fork keeps the upstream license, names the upstream authors in `.zenodo.json` and says
      in the README what it changed. Write "not a fork" otherwise. Evidence: not a fork. It vendors
      uport's `lib/ethr-did-registry` with its Apache-2.0 `LICENSE.md` and uses `forge-std` as a
      submodule (`.gitmodules`); the README's "Citation and license" section says vendored
      dependencies keep their licenses.
- [x] A tool has the tool README sections, `MAINTAINERS.md` and `SECURITY.md`. Write "results
      only" otherwise. Evidence: results only.

## Before going public

- [x] Every history warning of `just hygiene --publish` has been read. The history is not rewritten:
      each warning is either harmless once public or listed here with why it is acceptable. Evidence:
      `python3 scripts/hygiene.py --publish` gives 0 errors and 25 warnings:
      - 2 `private-link`: `verification/lean/CONTRACT.md` (removed in `0ba6113`) and
        `PAPER-COVERAGE.md` (`66f716a`) linked the private paper repository at commit `e53e483`.
        Once public, the old commits show a link that returns 404 to readers. Acceptable: it
        reveals the name of a private repository, nothing in it.
      - 20 `local-path`: 19 are in committed `node_modules/` and `hellocucumber/node_modules/`
        (commits `1344ee0`, `9f0f0d1`), upstream package docs and fixtures with their authors'
        example paths (the macOS home directories of two package authors, and a Windows
        placeholder). One is a coverage
        file (`a0a3d86`, `hellocucumber/coverage/tmp/…`) with the student's own macOS home
        directory, named after her first name. Acceptable: a first name, no secret.
      - 2 `layout`: no `tests/` and no `experiments/`. The repository uses Foundry's `test/` and
        `src/`, `offchain/test/`, and `results/` for recorded runs; the guide allows adapting.
      - 1 `readme`: no concept DOI badge yet. Expected before the first release.
- [ ] Every secret gitleaks ever found has been rotated: the key, token or wallet no longer
      works or holds anything. Evidence: not yet. gitleaks over the whole history (v8.30.1,
      `git /repo --redact`) finds 6 entries. 3 are the public Anvil account-zero key in
      `offchain/` test fixtures, accepted in `.gitleaksignore` with a reason. 3 are the
      issuer, holder and verifier private keys in `wallets.txt` (fingerprints
      `7e41dd034fb095a6bc2591352a8df217c3591443:wallets.txt:generic-api-key:3`, `…:7` and
      `e37175d04c8cae2fc3e36fef6c8b8a3758e28e0f:wallets.txt:generic-api-key:11`). The student
      rotates them; then the three fingerprints go into `.gitleaksignore` under a comment with
      the rotation date, and the workflow's gitleaks step turns green.
- [ ] No link points to a same-year TDK paper. Evidence: no link to a paper, the TDK portal or
      another student's paper repository (`git grep -nIiE "tdk\.bme\.hu|TDK2[0-9]"` outside
      `lib/` and `scripts/hygiene.py` finds nothing). One judgment call for Martin:
      `verification/lean/CONTRACT.md:23` and `:160`, and `verification/lean/scripts/check-distinct.py:6-7`,
      name Sinka Tibor's Lean work and link his public code repository
      `github.com/snktibor/argos-formal` (HTTP 200 anonymously). That is a same-year student's
      code, not a paper. `CONTRACT.md` is sealed.
- [ ] No AI app or bot is a collaborator or installed app with write access (Settings,
      Collaborators and GitHub Apps). Evidence: collaborators checked, apps not.
      `gh api repos/csillag2004/vc-rollup/collaborators` lists `BlackLight54 User` and
      `csillag2004 User`, no bot. Installed apps need the owner's view: Kamilla checks
      <https://github.com/csillag2004/vc-rollup/settings/installations>.
- [x] A `CLAUDE.md` or `AGENTS.md` that documents the code was renamed, so the archive keeps it.
      Evidence: `verification/lean/CLAUDE.md` became `verification/lean/README.md` in `0ba6113`.
      The root `.claude/` was local permission settings and was deleted (`cbea365`). `git ls-files`
      shows no other agent file.

## Release (the student's steps, after the pull request merges)

- [ ] The repository and its ghcr.io package are public, and an anonymous
      `docker manifest inspect ghcr.io/csillag2004/vc-rollup:v1.0.0` succeeds. Evidence:
- [ ] Zenodo is enabled for the repository, and release `v1.0.0` is tagged on the commit whose
      results match the paper. Evidence:
- [ ] The Zenodo record's files and metadata are checked, including both supervisors. The
      concept DOI badge in the README resolves. Evidence:
