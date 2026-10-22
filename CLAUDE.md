@AGENTS.md

## Working in a cloud session (Claude Code on the web)

- The cloud VM is **not on the tailnet** and has no access to any Monster Puppet server.
  Build, test and open a PR. Never try to deploy, SSH, or reach a real host from here.
- Work on the session branch and open a PR. Do not push to `main`.
- `make check` must pass before you open a PR. CI runs the same.
- Collector tests use captured output in `testdata/`. When you need real output from a
  host, say so in the PR and Marcus captures it locally. Do not invent it.
