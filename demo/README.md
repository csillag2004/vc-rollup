# Recorded demo

Run `just demo --smoke` from the repository root. It starts a fresh local Anvil chain,
runs the demo, and writes `out/demo/demo.cast` (asciinema v2), `out/demo/captions.vtt`,
and `out/demo/transcript.txt`. The recording contains the process's actual output and
elapsed timing. Replay it with `asciinema play out/demo/demo.cast`.

The CSV and provenance files are written to `out/`. Set `OUT` to choose
another results directory. Recording files are generated and excluded from Git.
