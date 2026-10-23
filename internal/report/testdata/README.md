# Collector fixtures

Captured output from the real hosts goes here, one file per command, with real IPs,
third-party hostnames and usernames replaced by placeholders (AGENTS.md rule 1).
Never write these by hand: Marcus captures them locally.

The collector tests in `checks_test.go` exercise each rule with small inline inputs
in the documented format of each source. Each capture below should get a test that
runs the collector's parser on it and asserts the expected state.

| File | Command / source | Host |
|---|---|---|
| `checkpoint.log.ok` | tail of `/p4/1/logs/checkpoint.log` after a good run | monster-p4 |
| `checkpoint.log.aborted` | a checkpoint.log from a failed run, if one is still around | monster-p4 |
| `offline_db.ls` | `ls -l --time-style=full-iso /p4/1/offline_db` | monster-p4 |
| `p4_license_u.txt` | `p4 -ztag license -u` as root, login noise included | monster-p4 |
| `p4d_V.txt` | `p4d -V` | monster-p4 |
| `firewall_list_all.txt` | `firewall-cmd --list-all` | monster-p4, jenkins |
| `dnf_updateinfo_security.txt` | `dnf -q updateinfo list --security` | monster-p4, jenkins |
| `apt_list_upgradable.txt` | `LC_ALL=C apt list --upgradable` | p4-game |
| `sshd_T_monster-p4.txt` | `/usr/sbin/sshd -T` as root (OpenSSH 8.0), captured 2026-10-23 | monster-p4 |
| `sshd_T_jenkins.txt` | `/usr/sbin/sshd -T` as root (OpenSSH 8.7), captured 2026-10-23 | jenkins |
| `journal_sshd.txt` | `journalctl -u sshd --since -24h -o cat`, a few failed-login lines | any |
| `win_tailscale_service.json` | `tailscaleServiceScript` in `win_parse.go` | jenkins-win |
| `win_fw_allow_any.json` | `firewallAnyScript` in `win_parse.go` | jenkins-win |
| `win_updates.json` | `windowsUpdateScript` in `checks.go` | jenkins-win |
| `win_4625.txt` | the RDP failed-login command in `examples/agent-jenkins-win.yaml` | jenkins-win |

Questions the captures answer:

- Does SDP rotate `checkpoint.log` per run? `p4.checkpoint` treats any "Aborting" in
  the file as the last run failing. If the log is appended to across runs, the rule
  must look only at the lines after the last start marker.
- Which `db.*` files in `offline_db` change on each journal replay.
- The `firewall_allow` list jenkins-win needs. Windows ships many enabled inbound
  rules with RemoteAddress Any, so `win.fw.allow_any` stays crit until the intended
  ones are listed by Name.
