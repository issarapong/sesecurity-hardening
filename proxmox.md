# Proxmox Host Hardening

Hardening of the Proxmox host (`1xxx.xxx.xxx.209`) — performed 2026-05-24 as the critical pre-build action item before starting Phase 0 of the `alldev-platform` migration (per the project redesign plan).

This doc captures **what was done, current state, how to access, recovery paths, and what's left to do**.

---

## Context

The Proxmox host had two critical exposure issues before hardening:

1. **PVE web UI (`:8006`) listening on public IP** — anyone on the internet could probe, brute-force, or exploit it. A successful compromise = takeover of every VM on the host.
2. **SSH (`:22`) accepting password authentication** — vulnerable to credential brute-force.

The host sits on a `/26` public block from ISP (`1xxx.xxx.xxx.192/26`, gateway `.193`) and the Proxmox host itself answers on `1xxx.xxx.xxx.209`. There is no upstream router doing NAT — Proxmox is the edge.

Other public IPs in the block stay untouched by this work (see project memory for full IP allocation including wp-prod at `.210`, edge-vm at `.220`, and legacy `.216/.217/.221`).

---

## What was done

### 1. SSH — key-only authentication

Dropped a new config snippet (preferred over editing the main `/etc/ssh/sshd_config` so a single `rm` reverts):

```
/etc/ssh/sshd_config.d/10-harden.conf
```

Contents:
```
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30s
```

Reloaded with `systemctl reload sshd`. Existing SSH session stayed alive; password auth confirmed disabled (`ssh -o PreferredAuthentications=password root@1xxx.xxx.xxx.209` returns `Permission denied (publickey).`).

### 2. PVE web UI — loopback only

Created `/etc/default/pveproxy` (didn't exist previously — Proxmox uses defaults when absent):

```
LISTEN_IP="127.0.0.1"
```

Reloaded with `systemctl restart pveproxy`. Confirmed bind with `ss -tlnp | grep 8006`:

```
LISTEN 0 4096 127.0.0.1:8006 ...
```

External verification from a different network returns `Connection timeout`:
```
$ curl -v -k --connect-timeout 5 https://1xxx.xxx.xxx.209:8006
* ipv4 connect timeout after 4998ms, move on!
```

`Timeout` (DROP) is preferable to `Connection refused` (RST) — silent to scanners.

### 3. Access path — SSH tunnel via Termius

PVE UI is now reachable **only** through an SSH-forwarded port. Termius port forwarding rule:

| Field | Value |
|---|---|
| Label | `proxmoxui` |
| Local port number | `8006` |
| Bind address | `127.0.0.1` |
| Intermediate host | `proxmox` (SSH host entry pointing at `1xxx.xxx.xxx.209`) |
| Destination address | `127.0.0.1` |
| Destination port number | `8006` |

> **Important — Destination must be `127.0.0.1`, not `1xxx.xxx.xxx.209`.**
> The destination is what the remote SSHd opens after the SSH session reaches Proxmox. Since pveproxy is bound to loopback only, the public IP no longer has a listener — connecting to `1xxx.xxx.xxx.209:8006` from the remote-side SSHd fails with RST. Using `127.0.0.1` makes it open to where pveproxy actually listens.

Same rule applies to plain CLI tunnels:
```
ssh -L 8006:127.0.0.1:8006 -N root@1xxx.xxx.xxx.209
```

Avoid `localhost` in either source or destination — modern `getaddrinfo` returns `::1` first, but pveproxy is bound to IPv4 only, so resolution can land on the unreachable IPv6 loopback.

With tunnel up, access PVE UI at `https://localhost:8006/` (browser shows cert warning — self-signed, accept).

### 4. fail2ban — SSH brute-force protection

Installed for log hygiene and to ban scanners that hammer `:22`. Even though SSH is key-only (brute-force can't succeed), public exposure means a steady ~150 attempts/hour. Without fail2ban the auth log fills and CPU wastes cycles on rejected handshakes.

```
apt install -y fail2ban
systemctl enable --now fail2ban
```

Debian's preset enables the `sshd` jail by default — no custom config needed. Verify with:

```
fail2ban-client status
fail2ban-client status sshd
```

Observed activity within 15 minutes of enabling:
- Total failed attempts: 39
- IPs banned: 1 (ban expired after default 10 min)
- Currently failed: 6 (scanners actively trying)

This confirms the internet is constantly probing :22; fail2ban handles it silently in the background.

### 5. pve-firewall — packet-layer defense in depth

Adds a kernel-level filter on top of pveproxy's loopback bind, so a future config slip (e.g. someone reverting `LISTEN_IP`) wouldn't re-expose `:8006`. Also enforces a default-deny posture for any future service that accidentally binds to a public interface.

Created `/etc/pve/firewall/cluster.fw`:

```
[OPTIONS]
enable: 1
policy_in: ACCEPT
policy_out: ACCEPT

[RULES]
IN ACCEPT -p icmp -log nolog
IN ACCEPT -p tcp -dport 22 -log nolog
IN DROP -p tcp -dport 8006 -log info
IN ACCEPT -p tcp -dport 80,443 -log nolog
IN DROP -log nolog
```

Rule rationale:
- `IN ACCEPT -p icmp` — allow ping/traceroute for diagnostics
- `IN ACCEPT -p tcp -dport 22` — SSH (already gated by key + fail2ban)
- `IN DROP -p tcp -dport 8006 -log info` — explicit deny on PVE UI, rate-limited NFLOG so we can audit who's probing it
- `IN ACCEPT -p tcp -dport 80,443` — needed for edge-vm later, wp-prod now, and legacy `.216/.217/.221` until decommission
- `IN DROP` — final explicit default-deny; everything not matched above gets silently dropped

`policy_in: ACCEPT` is paired with the explicit `IN DROP` at the end of the rules — this is safer than `policy_in: DROP` because if rules ever get loaded empty (file missing, parse error), the policy defaults to ACCEPT and we don't lock ourselves out. The explicit DROP at the end is visible and easy to comment for debugging.

Apply and verify:

```
pve-firewall compile    # check syntax + preview generated iptables
pve-firewall start
pve-firewall status     # expect "Status: enabled/running"
iptables -L PVEFW-HOST-IN -n -v --line-numbers
```

The `PVEFW-HOST-IN` chain shows our rules in order. Built-in Proxmox management ipset (`PVEFW-0-management-v4` covering `1xxx.xxx.xxx.192/27`) is generated by pve-firewall too, but it sits **after** our default-deny so it's effectively bypassed — fine for single-node operation. If a Proxmox cluster is added later, the rules need re-ordering to allow management subnet first.

Loopback (`-i lo -j ACCEPT`) is built into PVEFW-HOST-IN, so SSH-tunnel traffic forwarded to `127.0.0.1:8006` continues to reach pveproxy without going through the public-facing rules.

---

## Current state

| Surface | Before | After |
|---|---|---|
| `:22` (SSH) | Password auth open | Key-only, password/keyboard-interactive disabled, root via key only, MaxAuthTries 3 |
| `:22` brute-force | Unmonitored | fail2ban watching `auth.log`, bans after 5 fails / 10 min |
| `:8006` (PVE UI) | Listening on `0.0.0.0` | Bound to `127.0.0.1` AND dropped at firewall — two independent layers |
| Random ports | RST or timeout depending on service | All silent timeout (default DROP) |
| Access path | Direct browser to public IP | SSH tunnel only (loopback exempt from firewall) |

External probe of the public IP for `:8006` is now silent at both pveproxy layer (not listening) and firewall layer (DROP rule with logging). The host management plane is only reachable for clients who can already SSH in (key-based).

---

## Recovery / rollback paths

### "I lost my Termius config / can't tunnel"

1. SSH plainly: `ssh root@1xxx.xxx.xxx.209` (key still works).
2. Open a port forward in that session: `ssh -L 8006:127.0.0.1:8006 -N root@1xxx.xxx.xxx.209`.
3. Or recreate the Termius rule from the table above.

### "I broke pveproxy and PVE UI won't load"

In SSH (or PVE web shell if it still works):
```
rm /etc/default/pveproxy
systemctl restart pveproxy
```
Returns to default (binds all interfaces). PVE UI reachable on public IP again — undo the hardening for this single setting until the issue is diagnosed.

### "I broke SSH and locked myself out"

Use PVE web shell (Datacenter → Node → `>_ Shell` button in the PVE UI) — it doesn't go through sshd. From there:
```
rm /etc/ssh/sshd_config.d/10-harden.conf
systemctl reload sshd
```
Password auth comes back. (Use this only in a real emergency — and re-harden immediately after.)

If both SSH and PVE UI are broken, console access at the datacenter is the only option.

### "I'm at a network where my home IP isn't allowed"

Current hardening doesn't depend on home IP — access is via SSH tunnel which works from any network that can reach `1xxx.xxx.xxx.209:22`. As long as the key is on the device, no allowlist is needed.

When Headscale comes online (Phase 1 of alldev-platform), an additional access path opens via the Tailnet IP, providing redundancy.

### "fail2ban banned my own IP"

Possible if testing failed connections too aggressively from the same source. Recovery:

```
fail2ban-client unban <my-ip>
# or unban everyone:
fail2ban-client unban --all
```

If you can't SSH at all because of a ban, use the PVE web shell (which doesn't go through sshd) to run the unban.

### "pve-firewall is dropping legitimate traffic"

Existing SSH session is preserved by conntrack `RELATED,ESTABLISHED` — it won't drop you mid-session. But new connections may be affected. Disable while debugging:

```
# In the existing SSH session, or PVE web shell
pve-firewall stop
# or temporarily disable in config:
sed -i 's/^enable: 1/enable: 0/' /etc/pve/firewall/cluster.fw
pve-firewall reload
```

Then inspect `iptables -L PVEFW-HOST-IN -n -v` to see which rule is dropping packets (look at packet/byte counters per rule).

---

## Remaining hardening (open TODO)

These were planned but not completed in this session. None are blockers for starting alldev-platform Phase 0, but should be picked up alongside it:

- [ ] **2FA on `root@pam`** — Datacenter → Permissions → Two Factor → Add TOTP. ~5 minutes via PVE UI. Low impact at current state because PVE UI is already gated by SSH key (no direct internet exposure), but adds defense if Headscale or future LAN-internal access paths are introduced.
- [ ] **Audit `/root/.ssh/authorized_keys`** — there's an existing `ssh-rsa` entry from before this session; identify the source and remove if unknown / unused. Running:
  ```
  awk '{print $NF}' /root/.ssh/authorized_keys
  ```
  shows the comments — anything not recognized should be pruned.
- [ ] **Replace self-signed cert (optional)** — defer until edge-vm is up and Headscale provides a private trust path. Until then, browser cert warning is the operational signal that "this is the management plane, not a public service."
- [ ] **Tune fail2ban (optional)** — default Debian config is reasonable (5 retries / 10 min find time / 10 min ban). For more aggressive policy, write `/etc/fail2ban/jail.local` with `[DEFAULT] bantime = 1h, maxretry = 3, mode = aggressive`.
- [ ] **Cluster-aware firewall rule (deferred until cluster exists)** — if Proxmox cluster is added, re-order pve-firewall rules so the management subnet (`PVEFW-0-management-v4`) is allowed before the default `IN DROP`. Currently single-node so unreachable management ipset is fine.

### Completed in this session
- [x] SSH key-only authentication (drop-in `/etc/ssh/sshd_config.d/10-harden.conf`)
- [x] pveproxy bound to loopback (`/etc/default/pveproxy` LISTEN_IP=127.0.0.1)
- [x] SSH tunnel access path via Termius (destination `127.0.0.1` not public IP)
- [x] fail2ban installed and active on `sshd` jail
- [x] pve-firewall datacenter rules (default deny + explicit allows)

---

## References

- IP plan / VM mapping / overall design — see project memory `project_redesign_initiative.md` (Network plan section)
- ISP details: subnet `1xxx.xxx.xxx.192/26`, gateway `1xxx.xxx.xxx.193`, DNS `xxx.xxx.xxx.7`, `xxx.xxx.xxx.8`
- Larger CentralPaaS vision this fits into — `reference_centralpaas_context.md` (points to `/Volumes/Server/git-remote/github-issarapong/my-subscriber/aws-proxmox-paas/ARCHITECTURE.md`)
- Original Proxmox docs: `/etc/default/pveproxy.dist` on the host (defaults reference), `man pveproxy`
