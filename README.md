# Pi-hole on a Raspberry Pi 5: settings, performance and security

A practical guide for running Pi-hole v6 (FTL 6.x) as the DNS server of a home network on a
Raspberry Pi 5. It covers which settings to change, how to check what you have now, and how to
apply the changes through the web UI, the CLI, the REST API, or the bundled script.

Out of scope: encrypted DNS between Pi-hole and its upstream (DNS-over-TLS/HTTPS), and HTTPS for
the web UI. For a Pi-hole that is only reachable inside the home LAN, both add moving parts for
little gain.

Tested against Pi-hole Core v6.5, Web v6.6.1, FTL v6.8 (October 2026). Settings keys are the
`pihole.toml` names; they are identical in the web UI's **All settings** page, the CLI and the API.

| Path | What it is |
|---|---|
| `scripts/pihole_tool.rb` | Audit / apply / backup / blocklist tool |
| `scripts/pihole_bench.rb` | One-minute DNS benchmark with before/after comparison and tuning tips (§7.1) |
| `scripts/lib/pihole_kit.rb` | Shared code: API client, DNS client, profile and list helpers |
| `config/recommended.json` | The generic settings profile the tool audits and applies |
| `config/settings.local.example.json` | Template for your network-specific values |
| `config/settings.local.json` | Your values (git-ignored) |
| `*.local.md`, `backups/`, `benchmarks/` | Your notes, Teleporter backups and benchmark results (git-ignored; backups contain password hashes) |

The scripts need Ruby ≥ 3.1 and nothing beyond its standard library. On macOS use a current Ruby
(Homebrew, asdf, rbenv); the system Ruby 2.6 is too old. On the Pi itself: `sudo apt install ruby`.

---

## 1. Quick start

```bash
# 0. From any machine on the LAN (or on the Pi itself)
export PIHOLE_URL=http://<pi-ip>
ruby scripts/pihole_tool.rb audit                       # read-only; exit 2 = critical, 1 = warnings
ruby scripts/pihole_bench.rb --label baseline           # performance baseline (§7.1)

# 1. Back up before changing anything
ruby scripts/pihole_tool.rb backup                      # -> backups/pi-hole_*_teleporter_*.zip

# 2. Password first (the tool refuses to apply settings to a passwordless Pi-hole)
ruby scripts/pihole_tool.rb set-password                # or on the Pi: sudo pihole setpassword
#    then: Settings → Web interface / API → Enable 2FA, and "Configure app password" for scripts
export PIHOLE_PASSWORD='<app password>'                 # used by the tool from now on

# 3. Update Pi-hole (on the Pi)
sudo pihole -up

# 4. Network-specific values
cp config/settings.local.example.json config/settings.local.json   # edit LAN range, router IP, ACL

# 5. Apply the profile: dry run, then for real (takes a backup, applies in one request, verifies)
ruby scripts/pihole_tool.rb apply
ruby scripts/pihole_tool.rb apply --yes

# 6. Trim blocklists (see §6), rebuild gravity, audit again
ruby scripts/pihole_tool.rb lists overlap
ruby scripts/pihole_tool.rb lists disable <id> <id> --yes && ruby scripts/pihole_tool.rb gravity
ruby scripts/pihole_tool.rb audit
ruby scripts/pihole_bench.rb --label after-tuning       # compare with the baseline
```

Plus one change that no Pi-hole setting can do: **make the router hand out only the Pi-hole as DNS
server** (§2, finding 3).

---

## 2. Common findings

These are the problems that show up most often on otherwise working installs. `audit` checks
all of them.

| # | Finding | How to check | Fix |
|---|---|---|---|
| 1 | **No admin password.** Anyone on the LAN (IoT devices, guests) can disable blocking or change upstreams through the API. Before FTL 6.8, any website you open could do the same through your browser ([GHSA-322h-f873-hp54](https://github.com/pi-hole/FTL/security/advisories/GHSA-322h-f873-hp54)). | `curl -s http://<pi-ip>/api/auth`: `"no password set"` is bad | `sudo pihole setpassword`, then 2FA, plus an app password for integrations |
| 2 | **Outdated Pi-hole.** FTL 6.8 / Core 6.5 / Web 6.6.1 fixed 17 advisories, 5 of them high (root privilege escalation, file read). | Web UI footer, `pihole -v`, or `audit` | Teleporter backup, then `sudo pihole -up` |
| 3 | **Router hands out itself as second DNS server.** Clients pick whichever answers (macOS and Windows query both), so ads leak and those queries never show up in Pi-hole. | macOS `ipconfig getpacket en0 \| grep domain_name_server`, Linux `resolvectl dns`, Windows `ipconfig /all`. Then `dig +short @<router-ip> doubleclick.net`: a real IP means the router doesn't filter | Router DHCP: DNS = Pi-hole only. If two fields are required, enter the Pi-hole twice or add a second Pi-hole. If the router can't do it, use Pi-hole's DHCP server ([docs](https://docs.pi-hole.net/main/post-install)) |
| 4 | **IPv6 bypass.** The router advertises its own IPv6 DNS (RA/DHCPv6) next to the Pi-hole's IPv4. | `scutil --dns` / `resolvectl dns` lists an IPv6 server that isn't the Pi | Give the Pi a stable IPv6 (ULA) and advertise that, or disable IPv6 DNS advertisement on the router |
| 5 | **Mixed upstream providers** (e.g. Google + OpenDNS + Cloudflare). They differ in filtering, DNSSEC and logging, so the same name can get different answers. | Settings → DNS, or `audit` (also shows mean latency per upstream) | One provider pair, or a local recursive resolver (§9) |
| 6 | **The Pi-hole host is its own top client.** A container or app on the Pi polls one hostname every second or so. Cheap (cache hits), but it bloats the database and the stats. | Dashboard → Top clients; `audit` names the domain | Fix the app's config. `webserver.api.excludeDomains` only hides it from the views |
| 7 | **`dns.blockTTL` raised** (e.g. 3600). Clients cache "blocked" that long, so new allowlist entries seem not to work. | `sudo pihole-FTL --config dns.blockTTL` | Back to `2` |
| 8 | **Stacked blocklists.** Many popular lists are subsets of one another or full of dead domains. | `lists overlap` (§6) | Keep one main list + one threat list + targeted extras |
| 9 | **Extra services and SSH passwords on the DNS box** (VNC, SMB, media servers, torrent UIs). | `audit` port probe; `ssh -o PreferredAuthentications=none x@<pi-ip>` lists the auth methods | §8 |
| 10 | **OS out of regular support.** Debian 12 "bookworm" left regular security support on 2026-07-11 (LTS until 2028-06-30, fewer packages). | `cat /etc/os-release` | Plan a fresh Raspberry Pi OS "trixie" install; Raspberry Pi doesn't support in-place upgrades |

---

## 3. Recommended settings

`config/recommended.json` holds these values. Values marked *local* depend on your network and
belong in `config/settings.local.json`.

| Key | Recommended | Default | Why | Web UI |
|---|---|---|---|---|
| `dns.upstreams` | one pair, e.g. `9.9.9.9, 149.112.112.112` (Quad9) or `1.1.1.1, 1.0.0.1` (Cloudflare) | none | Consistent answers, one privacy policy. Quad9 also blocks known-malicious domains | Settings → DNS → Upstream DNS Servers |
| `dns.listeningMode` | `LOCAL` | `LOCAL` | Answers only directly connected subnets, so an accidental port forward can't create an open resolver. Use `ALL` if clients reach the Pi through a router (another VLAN, or a VPN that isn't terminated on the Pi) | Settings → DNS → Interface settings |
| `dns.blockTTL` | `2` | `2` | See finding 7 | All settings |
| `dns.replyWhenBusy` | `ALLOW` | `ALLOW` | During the brief gravity swap, answer instead of dropping (`DROP` makes clients time out) | All settings |
| `dns.domainNeeded` | `true` | `false` | Don't forward single-label names (`printer`) to the internet | Settings → DNS → Advanced DNS settings |
| `dns.bogusPriv` | `true` | `true` | Don't forward private-range reverse lookups to the internet | Settings → DNS → Advanced DNS settings |
| `dns.blocking.mode` | `NULL` | `NULL` | `0.0.0.0` / `::` → clients give up instantly | All settings |
| `dns.cache.size` | `10000` | `10000` | Enough for homes; lookups slow down above 10k. Raise only if `audit` reports live evictions | All settings |
| `dns.cache.optimizer` | `3600` | `3600` | Serve just-expired records instantly while refreshing | All settings |
| `dns.specialDomains.*` | all `true` | `true` | Stops iCloud Private Relay, Firefox auto-DoH and DDR from bypassing Pi-hole | All settings |
| `dns.dnssec` | `false` with validating upstreams | `false` | Quad9, Cloudflare and Google already validate; `audit` tests `dnssec-failed.org` | Settings → DNS → Advanced DNS settings |
| `dns.revServers` | *local*: `["true,192.168.1.0/24,192.168.1.1"]` | `[]` | Conditional forwarding: clients show by name instead of IP. Check first that the router answers: `dig +short -x <client-ip> @<router-ip>` | Settings → DNS → Conditional forwarding |
| `webserver.acl` | *local*: `+127.0.0.1,+[::1],+192.168.1.0/24` | empty = everyone | Web UI/API only from the LAN (add a VPN subnet if needed). Last match wins, the rest is denied | All settings |
| `ntp.ipv4.active` / `ntp.ipv6.active` | `false` unless clients use the Pi as time server | `true` | Closes UDP/123. Keep `ntp.sync` on | All settings |
| `database.maxDBdays` | `91` (or `30`) | `91` | Lower it only to save space; on NVMe, wear is a non-issue | Settings → Privacy |
| `misc.privacylevel` | `0` at home | `0` | Raise it if others on the network expect their queries not to be logged | Settings → Privacy |

---

## 4. Verify the current configuration

**Web UI.** Settings → **All settings**, and switch the top-right toggle to **Expert**. Values that
differ from the default carry a pencil icon; a circular-arrow icon means changing the value
restarts FTL.

**CLI on the Pi.**

```bash
sudo pihole-FTL --config dns.upstreams              # read one key
sudo grep -n '### CHANGED' /etc/pihole/pihole.toml | grep -v pwhash   # everything non-default (hide the hash)
pihole -v                                           # versions
pihole status
```

**API (any machine).** Every call except login needs the session id. Sessions are bound to your IP
and count against `webserver.api.max_sessions`, so log out when done.

```bash
PI=http://<pi-ip>
SID=$(curl -s -X POST "$PI/api/auth" -H 'Content-Type: application/json' \
      -d "{\"password\":\"$PIHOLE_PASSWORD\"}" | jq -r .session.sid)
curl -s "$PI/api/config/dns/upstreams" -H "sid: $SID" | jq
curl -s "$PI/api/config?detailed=true" -H "sid: $SID" | jq '.config.dns.blockTTL'   # value, default, description
curl -s "$PI/api/info/version" -H "sid: $SID" | jq
curl -s -X DELETE "$PI/api/auth" -H "sid: $SID"
```

**DNS behaviour (from a client).**

```bash
dig +short @<pi-ip> doubleclick.net          # 0.0.0.0 → blocking works
dig @<pi-ip> dnssec-failed.org | grep status # SERVFAIL → DNSSEC is validated somewhere in the chain
dig @198.41.0.4 . NS +norec +time=3          # 'aa' flag, no 'ra' → no ISP DNS interception (needed for unbound)
# What this client was told to use (expect only Pi-hole addresses):
ipconfig getpacket en0 | grep domain_name_server      # macOS
resolvectl dns                                        # Linux
ipconfig /all | findstr /i "DNS"                      # Windows
dig +short @<other-dns-server> doubleclick.net        # a real IP here = leak
```

**All of the above at once:** `ruby scripts/pihole_tool.rb audit`. It compares every profile key,
versions, upstreams, cache health, the top clients, blocklist redundancy, this client's DNS servers
(leak test), and probes common TCP ports and the SSH auth methods. Options: `--no-client-checks`
when running on the Pi itself, `--no-port-scan`, `--test-domain <a domain you block>`.

---

## 5. Apply the settings

Use one method at a time. Applying an API change while a CLI change is restarting FTL can lose
one of them.

### 5a. Web interface

1. **Settings → DNS**: upstream servers (untick the presets, enter your pair under *Custom DNS
   servers*), *Interface settings* (listening mode), *Advanced DNS settings*, *Conditional
   forwarding*. Click **Save & Apply**.
2. **Settings → All settings** (Expert): `dns.blockTTL`, `dns.replyWhenBusy`, `dns.blocking.mode`,
   `dns.specialDomains`, `webserver.acl`, `ntp.*`, `webserver.api.password`.
3. **Settings → Web interface / API**: *Enable two-factor authentication*, *Configure app password*.
4. **Group Management → Lists**: toggle lists off (keep them so the change can be undone), then
   **Tools → Update Gravity**.
5. **Settings → Teleporter**: export a backup before and after.

### 5b. CLI on the Pi

`pihole-FTL --config <key> <value>` writes `/etc/pihole/pihole.toml`, and the running FTL picks it
up (keys marked as restart-required restart FTL). `--config -t <key> <value>` only validates.

```bash
sudo pihole-FTL --teleporter                                    # backup zip in the current directory
sudo pihole setpassword
sudo pihole -up

sudo pihole-FTL --config dns.upstreams '["9.9.9.9","149.112.112.112"]'
sudo pihole-FTL --config dns.listeningMode LOCAL
sudo pihole-FTL --config dns.blockTTL 2
sudo pihole-FTL --config dns.replyWhenBusy ALLOW
sudo pihole-FTL --config dns.domainNeeded true
sudo pihole-FTL --config dns.bogusPriv true
sudo pihole-FTL --config dns.revServers '["true,192.168.1.0/24,192.168.1.1"]'
sudo pihole-FTL --config webserver.acl '+127.0.0.1,+[::1],+192.168.1.0/24'
# only if no device uses the Pi as its NTP server:
sudo pihole-FTL --config ntp.ipv4.active false
sudo pihole-FTL --config ntp.ipv6.active false

sudo pihole -g                                                  # rebuild gravity after list changes
```

### 5c. REST API

The `PATCH /api/config` body must be wrapped in `"config"`; without it the API returns
`400 No "config" object in body data`. A single PATCH with all changes is applied as one unit.

```bash
curl -s -X PATCH "$PI/api/config" -H "sid: $SID" -H 'Content-Type: application/json' -d '{
  "config": {
    "dns": {
      "upstreams": ["9.9.9.9", "149.112.112.112"],
      "blockTTL": 2, "replyWhenBusy": "ALLOW", "domainNeeded": true, "bogusPriv": true,
      "revServers": ["true,192.168.1.0/24,192.168.1.1"]
    },
    "webserver": { "acl": "+127.0.0.1,+[::1],+192.168.1.0/24" }
  }
}' | jq '.config.dns.blockTTL'

# Set the admin password (all existing sessions become invalid)
curl -s -X PATCH "$PI/api/config" -H "sid: $SID" -H 'Content-Type: application/json' \
     -d '{"config":{"webserver":{"api":{"password":"<new password>"}}}}'

# Disable a list. PUT replaces comment and groups, so send the current ones back;
# ?type= is required.
URL=$(jq -rn --arg u 'https://example.org/list.txt' '$u|@uri')
curl -s -X PUT "$PI/api/lists/$URL?type=block" -H "sid: $SID" -H 'Content-Type: application/json' \
     -d '{"enabled": false, "comment": null, "groups": [0]}'

curl -s -X POST "$PI/api/action/gravity" -H "sid: $SID"     # rebuild gravity (streams progress)
curl -s "$PI/api/teleporter" -H "sid: $SID" -o backup.zip   # backup
```

Every Pi-hole serves the API reference for its exact version at `http://<pi-ip>/api/docs`.

### 5d. The script

```bash
ruby scripts/pihole_tool.rb apply                            # dry run: lists every change
ruby scripts/pihole_tool.rb apply --yes                      # backup → one PATCH → poll until verified
ruby scripts/pihole_tool.rb apply --yes --only dns.blockTTL,dns.upstreams
```

What `apply` does:
- Refuses to run while no password is set.
- Refuses an `webserver.acl` that would lock out the machine running it.
- Skips *local* keys you haven't filled in, and never touches advisory keys (`apply: false`).
- If your Pi-hole redirects HTTP to HTTPS, the tool follows the redirect; add `--insecure` for
  Pi-hole's self-signed certificate. Global options (`--url`, `--insecure`, …) work before or after
  the command.

Other commands: `backup`, `set-password`, `gravity`, `lists show|overlap|enable|disable`.
Authentication comes from `$PIHOLE_PASSWORD` (an app password avoids 2FA prompts) or an
interactive prompt; `$PIHOLE_TOTP` supplies a 2FA code non-interactively.

---

## 6. Blocklists

More lists ≠ more blocking. Each extra list adds update time, false positives to chase, and
usually mostly duplicates or dead domains. Whichever lists you use, the same structure works:

- **One main list** for ads and tracking. If the maintainer offers tiers (light / normal /
  aggressive), pick one: higher tiers usually contain the lower ones, so stacking tiers only adds
  duplicates. Aggressive tiers mean a few allowlist entries.
- **One threat list** (malware, phishing, scams). Smaller variants exist for limited hardware.
- **Targeted extras** with a distinct purpose, e.g. a DoH/VPN-bypass list that keeps browsers and
  apps from going around Pi-hole, or a privacy/telemetry list.
- **Skip** lists your main list already includes. Most comprehensive lists document what they
  merge in; check before adding a narrow list on top.

Measure your own set with `ruby scripts/pihole_tool.rb lists overlap --base <id>,<id>`. `--base`
names your main lists by id or URL substring (ids: `lists show`); without it the tool only
auto-detects HaGeZi main/threat lists. It downloads every enabled list, counts how many entries
are not already covered by the base lists (counting parent-domain matches the way Pi-hole treats
Adblock-format entries), and resolves a random sample of those unique entries against a
**non-filtering** resolver to estimate how many are dead. Output columns: entries, % not in base,
% of those that are dead.

Reading it:

| Result | Meaning | Action |
|---|---|---|
| ≈0% not in base | Redundant: fully covered by your main lists | Disable |
| High % not in base, high % dead | Mostly stale entries | Disable, or keep only if it targets a threat you care about |
| High % not in base, low % dead | Live, distinct coverage | Keep |
| High % unique but a different purpose (e.g. DoH bypass) | Complements rather than overlaps | Keep if you want that purpose |

Large threat feeds often add many resolvable domains but also more false positives; keep them only
if you accept the allowlist work. Disable instead of deleting, then rebuild gravity.

`overlap` compares lists with each other. **`lists usage`** answers the practical question: what does
each list block **on your network**? It takes the domains Pi-hole actually blocked over the last
N days (`--days 30`, from the query database) and checks each one against every enabled list:

```bash
ruby scripts/pihole_tool.rb lists usage --days 30
```

- *matched*: blocked queries whose domain is on the list.
- *only-this*: queries that would no longer be blocked if you disabled the list, with the top
  examples ("only here: …").

A list with 0 *only-this* queries over a month adds nothing for your traffic today. A list that
carries a lot of *only-this* traffic deserves a look at those domains: they are either genuinely
useful blocks or the source of your allowlist work. Pi-hole's own per-query `list_id` is not used: it
names a single list per domain (on FTL 6.8 often a placeholder), which hides overlap.

List size costs no measurable query latency (gravity lookups are indexed; see the benchmark's
gravity-lookup metric). What extra lists do cost: a longer weekly gravity rebuild, more RAM, and more
false positives to chase.

---

## 7. Performance on a Raspberry Pi 5

A Pi 5 is far more than Pi-hole needs. One measured home network (~50 clients, ~110k
queries/day) ran at ~0.5% CPU with 91% of answers served from cache.

- **Don't tune the cache.** If the `dns_cache_live_freed` counter (`/api/info/ftl`, or the `audit`
  line) is 0, the default 10k entries are enough. A bigger cache only makes lookups slower.
- **Watch co-located workloads.** Media transcoding or torrent clients on the same Pi can push the
  15-minute load above the core count (Pi-hole then shows a LOAD warning). FTL already runs at
  `misc.nice = -10`. To keep a core free, cap containers (`docker run --cpus=3 …` or
  `deploy.resources.limits.cpus` in compose).
- **Storage.** Boot from NVMe (M.2 HAT) or a USB SSD if you can. On a microSD card, use a good A2
  card and consider [log2ram](https://github.com/azlux/log2ram) and a lower `database.maxDBdays`
  to cut writes. On NVMe neither is needed.
- **Power and heat.** Use the official 27 W USB-C supply (undervoltage causes random hangs) and the
  Active Cooler or a case fan. `vcgencmd get_throttled` should print `throttled=0x0`; 
  `vcgencmd measure_temp` should stay well below 80 °C.
- **Firmware.** `sudo rpi-eeprom-update -a` keeps the bootloader current (it carries NVMe/USB boot
  and power-management fixes).
- **Network.** Use wired Ethernet and a static IP (or a DHCP reservation). If Wi-Fi is unused,
  disable it with `dtoverlay=disable-wifi` in `/boot/firmware/config.txt` (also `disable-bt`).
- **Upstream latency only matters for cache misses** (~5–10% of queries). `audit` prints the mean
  response time per upstream; pick the fastest provider you trust.
- **Chatty clients.** Fix apps that resolve the same name every second at the source; that is
  cheaper than any server-side tuning.

### 7.1 Benchmark before and after every change

`scripts/pihole_bench.rb` measures how fast Pi-hole actually answers, explains the results, and
compares each run with the previous one. A run takes a few seconds; 60 s is the hard limit
(`--max-seconds`).

```bash
ruby scripts/pihole_bench.rb --label baseline           # saved to benchmarks/ (git-ignored)
sudo pihole-FTL --config dns.upstreams '["1.1.1.1","1.0.0.1"]'   # change ONE thing
ruby scripts/pihole_bench.rb --label cloudflare         # report + automatic compare with the previous run

ruby scripts/pihole_bench.rb history                    # one line per run
ruby scripts/pihole_bench.rb compare                    # last two runs
ruby scripts/pihole_bench.rb compare --before baseline --after cloudflare   # medians per label
```

For trustworthy numbers:
- Change one setting at a time.
- Benchmark from a **wired** client.
- Run each setup 2–3 times with the same label and compare labels. On Wi-Fi, back-to-back runs
  differ by up to ~20% on cached answers, and cache misses (which depend on the internet path)
  ranged 15–35 ms over one day. `compare` marks changes inside these noise floors `≈`.
- Compare runs taken close together in time, especially for the cache-miss and upstream metrics.
- Set `$PIHOLE_PASSWORD` (an app password is enough). Without it, the server-side metrics and the
  record of which settings changed between runs are missing.

**What it measures** (about 420 queries to Pi-hole per run, mostly cache hits):

| Phase / metric | What it tells you | Healthy (wired LAN) | Settings and fixes that move it |
|---|---|---|---|
| Network RTT (TCP handshake to the Pi) | Baseline that every answer includes | <1 ms wired, 2–10 ms Wi-Fi | Not Pi-hole: cabling, Wi-Fi, switch |
| Cached answer p50 / p95, and *Pi-hole time per cached answer* (p50 − RTT) | Pure Pi-hole speed: shared-memory lookup, no upstream | overhead <1 ms; p95 <3× p50 | CPU contention (other containers, transcoding), `misc.nice` (-10), throttling (`vcgencmd get_throttled`), SD-card I/O stalls |
| Blocked, repeated domain | Cost of answering a known-blocked name | ≈ cached | Nothing to tune if equal |
| Blocked, **new** subdomain (gravity lookup) | Each new name is checked against the gravity database and every regex. Uses random subdomains of a blocked domain on an Adblock-style list | ≤ cached + 1 ms | Fewer/overlapping lists (`pihole_tool.rb lists overlap`), fewer deny regexes (use `\|\|domain^` entries instead), NVMe/SSD for `gravity.db` |
| Cache miss via Pi-hole p50 / p95 | Random names that no cache can hold: upstream round trip + recursion | 10–40 ms with public upstreams; 50–300 ms with unbound | `dns.upstreams` (closest/fastest provider), `dns.dnssec`, the Pi's uplink |
| Upstreams table: *popular* / *miss* / *Pi-hole mean* | Each configured upstream plus Cloudflare, Quad9 and Google as reference, queried directly from the client. *Popular* = names the upstream has cached (the typical forwarded query); *Pi-hole mean* = Pi-hole's own statistics from real traffic (best evidence) | One provider pair, all similar | Drop slow upstreams; Pi-hole keeps sending a share of queries to every configured server to re-measure it |
| Forwarding overhead (miss via Pi-hole − same miss directly) | What Pi-hole adds on a cache miss | <5 ms | `dns.dnssec=true` with an already validating upstream doubles the validation work; a local unbound is slower on misses by design (`prefetch`, `serve-expired` help); high load |
| Burst throughput, p95, failures | 25 parallel clients; saturation and dropped packets | 0 failures; any q/s figure is enough for a home | Timeouts: CPU or Wi-Fi saturation, `dns.replyWhenBusy=DROP`. REFUSED: rate limit (`dns.rateLimit`) |
| Server: cache hit %, live evictions | From Pi-hole's statistics (24 h / since FTL start) | Evictions = 0 | Evictions > 0: raise `dns.cache.size` moderately (×2, stay ≤ 50k). Keep `dns.cache.optimizer=3600` |
| Server: load, FTL CPU, temperature | Is the Pi itself the bottleneck? | Load < 70% of cores, <80 °C | Move heavy workloads, add cooling |

Settings that **don't** improve speed on a Pi 5, despite common advice: a cache larger than needed
(Pi-hole's docs: lookups slow down past 10k entries), and `dns.blockTTL` above a few seconds (fewer
repeat queries, but allowlisting then seems not to work).

Safety: Pi-hole REFUSES a client that sends more than `dns.rateLimit.count` queries per interval
(default 1000/60 s), and that client then can't resolve anything until the interval ends. The
benchmark sizes its burst to stay under 45% of the limit, waits automatically when recent runs
would push it over, and flags any run that still got REFUSED answers as invalid. All synthetic
names start with `pihole-bench-`. To hide them from the query log, add the regex `pihole-bench-`
to `webserver.api.excludeDomains`.

---

## 8. Security hardening

**Pi-hole**
1. Admin password, 2FA, and an app password for scripts and integrations (Settings → Web
   interface / API). Recovery when the 2FA device is lost:
   `sudo pihole-FTL --config webserver.api.totp_secret ''`.
2. Keep current: read the [release notes](https://pi-hole.net/blog/), take a Teleporter backup, run
   `sudo pihole -up`. Watch the security advisories of
   [FTL](https://github.com/pi-hole/FTL/security/advisories),
   [Core](https://github.com/pi-hole/pi-hole/security/advisories) and
   [Web](https://github.com/pi-hole/web/security/advisories) (GitHub → Watch → Custom → Security alerts).
3. `webserver.acl` limited to LAN/VPN. The web UI stays on plain HTTP: it is only reachable inside
   the LAN (item 4), so this guide doesn't set up HTTPS.
4. **Never port-forward 53, 80 or 443** to the Pi. A Pi-hole reachable from the internet is an open
   resolver that can be abused for DDoS amplification. For remote use, connect through a VPN
   (WireGuard) into the LAN. Check that UPnP can't open ports on its own.
5. Keep `dns.listeningMode = LOCAL` unless you route clients from other subnets.
6. Keep the anti-bypass pieces on: `dns.specialDomains.*`, a DoH blocklist, and the router
   advertising only the Pi-hole as DNS (IPv4 and IPv6). For stricter setups, block outbound
   TCP/UDP 53 and 853 on the router for everything except the Pi-hole.
7. Teleporter backups contain password hashes: store them privately (`backups/` is git-ignored and
   the tool writes them with mode 600).

**Operating system**
1. Updates: `sudo apt update && sudo apt full-upgrade`, then automatic security updates:
   `sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`.
2. Supported release: Debian 12 has been in LTS since 2026-07-11. Move to Raspberry Pi OS based on
   Debian 13 "trixie" with a fresh install (restore Pi-hole from Teleporter), see §8.1.
3. SSH: keys only, no root login. Copy your key first (`ssh-copy-id user@<pi-ip>`), then:
   ```bash
   printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n' \
     | sudo tee /etc/ssh/sshd_config.d/10-hardening.conf
   sudo sshd -t && sudo systemctl reload ssh
   ```
4. Turn off what you don't use: VNC (`sudo raspi-config nonint do_vnc 1`), Samba, Bluetooth.
   Change default passwords of other web UIs on the box (torrent clients often ship with one).
   **If you do use VNC**, check its security first: `audit` reads the security types the server offers.
   Raspberry Pi OS's wayvnc offers only encrypted logins with the Pi account's password, so use a
   strong password for that account (it matters even with SSH set to keys only). Then allow port
   5900 only from the PCs that use it. Run `sudo apt install nftables` first, then **replace** the
   package's `/etc/nftables.conf`: its default starts with `flush ruleset`, which would wipe Docker's
   rules whenever it is reloaded.
   ```
   #!/usr/sbin/nft -f
   # Only the listed PCs may reach VNC (5900); all other sources are dropped.
   # No "flush ruleset": that would also wipe Docker's rules.
   table inet vnc_guard
   delete table inet vnc_guard
   table inet vnc_guard {
     set vnc_clients {
       type ipv4_addr
       elements = { 192.168.1.10 }
     }
     chain input {
       type filter hook input priority 0; policy accept;
       tcp dport 5900 ip saddr != @vnc_clients drop
       meta nfproto ipv6 tcp dport 5900 drop
     }
   }
   ```
   Load it with `sudo nft -f /etc/nftables.conf && sudo systemctl enable nftables`. Give each allowed
   PC a DHCP reservation so its address doesn't change. To add a PC, put its IP in `elements`; for VNC
   over the VPN, add the VPN client IPs too.
5. Docker: ports a container publishes bypass ufw/iptables INPUT rules. Bind them to the LAN IP
   (`-p 192.168.1.2:8080:8080`) or filter in the `DOCKER-USER` chain. Pi-hole itself runs best
   natively, outside Docker.
6. Optional host firewall (if Docker is not in use), e.g. ufw allowing 22, 53/tcp+udp, 80, 443
   from the LAN only.

### 8.1 Moving from bookworm to trixie without breaking anything

The kernel is not the problem. Raspberry Pi OS ships Raspberry Pi's own kernel (6.12 on both
releases), which keeps getting updates on bookworm. What ages is the Debian 12 userland: security
fixes now come from Debian LTS, which covers fewer packages, and end on 2028-06-30. So there is time,
but plan the move. Raspberry Pi doesn't support in-place upgrades between major releases; do a fresh
install.

**1. Check readiness (read-only, from your computer):**

```bash
ruby scripts/trixie_check.rb --host <user>@<pi-ip>
```

It collects an inventory over SSH and saves it to `inventory/` (git-ignored). Then it reports:
- **BLOCK**: third-party APT repositories without a trixie suite.
- **WARN**: hand-installed packages that don't exist in trixie (checked against the Debian and
  Raspberry Pi trixie package indexes, about 15 MB of downloads), plus the Debian 13 release-note
  changes that apply to you: `/etc/sysctl.conf` no longer read, `~/.pam_environment` ignored by SSH,
  DSA keys removed, `/tmp` in RAM.
- **TODO**: everything to carry over: enabled services, Docker containers with their compose files
  and bind-mounted data, WireGuard/PiVPN, Samba shares, VNC, firewall, crontabs, fstab mounts,
  `config.txt` tweaks and home directories.
- The EEPROM **boot order**, and whether a test card would boot before your current system.

Commands that need root run with `sudo -n` and are skipped if sudo would ask for a password. Re-run the
analysis on a saved inventory with `--from inventory/<file>`.

**2. Test on a second disk; the current system stays untouched.** With the default boot order
(`0xf461`: SD card, then NVMe, then USB) a Pi that runs from NVMe boots an inserted SD card first.
Flash Raspberry Pi OS trixie (64-bit; Desktop if you use VNC) to a spare card with Raspberry Pi
Imager, boot it, and rebuild following the TODO list. The old system can be mounted read-only to copy
from: `sudo mount -o ro /dev/nvme0n1p2 /mnt`. To go back, shut down and remove the card. Pi-hole
answers from whichever system is running, so test at a quiet time; the IP stays the same if the router
has a DHCP reservation for the Pi's MAC address.

**3. Rebuild order on the test system:** Pi-hole (installer, then import the Teleporter export) →
WireGuard (copy `/etc/wireguard`; PiVPN 4.10.1+ also installs on trixie) → Docker from Docker's trixie
repository + compose files + data → Samba (`smbpasswd -a` per user) → VNC, SSH keys, firewall, cron.
Then verify with `ruby scripts/pihole_tool.rb audit` and `ruby scripts/pihole_bench.rb --label trixie`
against the bookworm baseline.

**4. Switch over:** run from the card for about a week. To make it permanent, take a final backup of
the old system (Teleporter export plus the data paths from the TODO list), then copy the card onto the
NVMe drive with SD Card Copier (Desktop: Accessories → SD Card Copier) [inference: still bundled on
trixie]. That overwrites the old bookworm system, so it is the point of no return; until then, removing
the card brings everything back.

---

## 9. Optional: Unbound as a local recursive resolver

Instead of forwarding to a public provider, Pi-hole can ask a local
[unbound](https://docs.pi-hole.net/guides/dns/unbound/), which walks the DNS tree itself.
This is not DNS-over-TLS; it simply removes the single upstream that sees every lookup.

- **Gains:** no single provider sees all your queries; DNSSEC is validated locally.
- **Costs:** first lookups of uncached names take 100–1000 ms instead of ~10–30 ms (with a 90%+
  cache hit rate you rarely notice); one more service to keep updated.
- **Before installing**, run the root-server tests from the guide (UDP, TCP and `version.bind`
  against `198.41.0.4`). Some ISPs and routers intercept port 53, and unbound then fails in
  confusing ways.
- Set upstream to `127.0.0.1#5335` only. On Debian, disable `unbound-resolvconf.service` as the
  guide describes. Unbound must listen on 127.0.0.1 only; `audit` flags 5335/tcp if it's reachable
  from the LAN.

---

## 10. Redundancy

When the only Pi-hole is down, all name resolution stops. The fix is a **second Pi-hole**, not a
non-filtering fallback (that's finding 3). Any small always-on machine works (a Pi Zero 2 W, an
old Pi, a VM or container on a NAS). Keep the two in sync with
[nebula-sync](https://github.com/lovelaze/nebula-sync) (the v6-compatible successor of
gravity-sync) and hand out both addresses via DHCP.

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Web UI/API stops answering right after a settings change | FTL restarts for some keys. If it doesn't come back within ~30 s: `sudo systemctl restart pihole-FTL` (Docker: `docker restart <container>`). Seen once in testing on Docker after changing `webserver.port` |
| Locked out by `webserver.acl` | On the Pi: `sudo pihole-FTL --config webserver.acl ''` |
| Allowlisted domain still blocked | Client-side cache: lower `dns.blockTTL`, flush the client's DNS cache, and make sure the browser isn't using its own DoH |
| `apply` reports "NOT applied" | A later CLI/UI edit overwrote it, or an environment variable (Docker `FTLCONF_*`) forces the value. Settings forced by environment are read-only (padlock icon in All settings) |
| Lost 2FA device | `sudo pihole-FTL --config webserver.api.totp_secret ''` |

---

## Sources

- Pi-hole configuration reference: <https://docs.pi-hole.net/ftldns/configfile/>
- Pi-hole FTL v6.8 / Core v6.5 / Web v6.6.1 release notes (security fixes):
  <https://pi-hole.net/blog/2026/10/17/pi-hole-ftl-v6-8-web-v6-6-1-and-core-v6-5-released/>
- Pi-hole post-install (router / DHCP setup): <https://docs.pi-hole.net/main/post-install>
- Pi-hole + unbound guide: <https://docs.pi-hole.net/guides/dns/unbound/>
- Pi-hole API authentication: <https://docs.pi-hole.net/api/auth/>
- HaGeZi DNS blocklists and FAQ: <https://github.com/hagezi/dns-blocklists>
- Debian 12 life cycle: <https://www.debian.org/releases/bookworm/>
- Raspberry Pi on bookworm → trixie upgrades: <https://forums.raspberrypi.com/viewtopic.php?t=392376>
- nebula-sync: <https://github.com/lovelaze/nebula-sync>
