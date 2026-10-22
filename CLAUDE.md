@AGENTS.md

## Working in a cloud session (Claude Code on the web)

- The cloud VM is **not on the tailnet** and has no access to any Monster Puppet server.
  Build, test and push. Never try to deploy, SSH, or reach a real host from here.
- Commit and push directly to `main`. No session branch, no PR.
- `make check` must pass before you push. CI runs the same.
- Collector tests use captured output in `testdata/`. When you need real output from a
  host, say so in the commit message and Marcus captures it locally. Do not invent it.
