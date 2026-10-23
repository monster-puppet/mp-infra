@AGENTS.md

## Working in a cloud session (Claude Code on the web)

- The cloud VM is **not on the tailnet** and has no access to any Monster Puppet server.
  Build, test and push. Never try to deploy, SSH, or reach a real host from here.
- Commit and push directly to `main`. No session branch, no PR.
- `make check` must pass before you push. CI runs the same.
- Collector tests use captured output in `testdata/`. When you need real output from a
  host, say so in the commit message and Marcus captures it locally. Do not invent it.

## Where it actually runs (production)

- `mpinfra serve` runs on the **exe.dev VM `mp-infra`**, not on the jenkins droplet
  (docs/spec.md predates that). Tailnet IP 100.86.1.7. The UI is at
  https://mp-infra.tailce223.ts.net behind `tailscale serve`, with Google sign-in.
  `infra.monster-puppet.com` redirects there.
- Deploy is `scripts/deploy.sh`, run by Marcus from TACCO-PC in a real terminal (it asks
  for sudo passwords). It ships origin/main to the server and every agent in
  `deploy/hosts`; `scripts/deploy.sh --agents` or `scripts/deploy.sh <host>...` narrow
  it. On the VM, `/update-mpinfra.sh` (pull, `make check`, build, install, roll back if
  `http://127.0.0.1:8098/healthz` fails) is what deploy.sh runs for the server. So when
  you report a change, tell Marcus to run `scripts/deploy.sh`, or `scripts/deploy.sh
  -n` first to see what ships. Never point him at jenkins.
- **Never bind the UI to port 8000 there.** exe.dev's proxy publishes port 8000 to the
  internet as mp-infra.exe.xyz, so the dashboard was briefly public on 2026-10-22.
- Reporting hosts: monster-p4, jenkins, jenkins-win (tag:ci-untrusted), and p4-game
  (tag:public-server, P4 deliberately public). Each must be listed under `hosts:` in the
  server config before it gets a token, or the server refuses to start.
