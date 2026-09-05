# lockin

A macOS focus blocker written in Go. One JSON configuration, one CLI, and a root launchd daemon. No app window, menu bar item, browser extension, account, or external Go dependencies.

- Manual sessions with durations such as `30s`, `90m`, or `1h30m`.
- Blocklist or allowlist policies for DNS names, IPv4/IPv6 addresses, and CIDRs.
- Optional weekly or one-time schedules, including overnight windows.
- One emergency break per **manual** session, lasting at most **three minutes**.
- **No emergency break for scheduled sessions.** No stop, shorten, or reset command.
- Active restrictions, deadlines, and break usage survive daemon restarts and reboots. Configuration reloads cannot loosen a running session.

## Install

Requires **macOS** and **Go 1.26+**. The daemon uses macOS's built-in `pfctl`, `dig`, `dscacheutil`, and `launchctl`. Administrator authorization is required to install the daemon and change system network rules; normal CLI use does not require `sudo`.

```sh
brew install go  # if Go is not installed

git clone https://github.com/basedcorp99/lockin-cli.git
cd lockin-cli
./install.sh
```

The installer builds locally and creates `~/.config/lockin/config.json` only if it does not already exist. The example schedule is **disabled**, so installation does not unexpectedly start a lock. Existing session state is preserved when reinstalling or upgrading.

Edit the configuration before starting your first session:

```sh
$EDITOR ~/.config/lockin/config.json
lockin check
lockin reload
lockin start 90m
```

`/usr/local/bin` must be on your `PATH`; otherwise use `/usr/local/bin/lockin` directly.

A custom configuration path is supported:

```sh
./install.sh /absolute/path/to/config.json
lockin reload --config /absolute/path/to/config.json
```

Or build and install explicitly:

```sh
go build -trimpath -o lockin .
./lockin init                       # refuses to overwrite existing configuration
./lockin check
sudo ./lockin install --owner "$(id -u)" --config "$HOME/.config/lockin/config.json"
```

## Commands

| Command | Effect |
| --- | --- |
| `lockin start 1h30m` | Start one manual session using the accepted configuration. |
| `lockin break` | Consume that manual session's only emergency break. |
| `lockin status` | Show active sessions, deadlines, break allowance, and enforcement errors. |
| `lockin status --json` | Return structured state and enforcement health. Exits nonzero on an error. |
| `lockin check [--config PATH]` | Validate a configuration without changing daemon state. |
| `lockin reload [--config PATH]` | Accept a configuration without restarting the daemon. |
| `lockin init [--config PATH]` | Create a minimal example, never overwriting an existing file. |
| `lockin help` | Show the built-in command reference. |

Durations use [Go duration syntax](https://pkg.go.dev/time#ParseDuration): `45s`, `90m`, `2h`, `1h15m30s`, or `1.5h`. Units are required, the minimum is one second, and overflow is rejected. For a day, use `24h`; `d` and `w` are not supported.

Only one manual session can be active at once. A second `start` cannot replace, shorten, extend, or reset it. A manual session can overlap scheduled sessions, but all active restrictions apply together.

### Emergency break

- Exactly one use per manual session, not a daily quota.
- Lasts three minutes, or until the session's end if sooner.
- The session timer continues during the break.
- A schedule starting during a break immediately ends the break, with no refund.
- A break cannot start while any scheduled session is active.
- Reloading or restarting does not restore a consumed use.

## Configuration

Start with [`config.example.json`](config.example.json). Unknown fields, malformed hosts, duplicate schedule IDs, invalid timezones, and invalid intervals are rejected.

```json
{
  "mode": "blocklist",
  "hosts": ["example.com", "203.0.113.0/24", "2001:db8::/32"],
  "timezone": "Europe/London",
  "schedules": [
    {
      "id": "weekday-work",
      "days": ["mon", "tue", "wed", "thu", "fri"],
      "start": "09:00",
      "end": "17:00"
    },
    {
      "id": "sunday-night",
      "enabled": false,
      "days": ["sun"],
      "start": "22:30",
      "end": "07:00"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `mode` | Required: `blocklist` blocks listed destinations; `allowlist` permits only listed destinations, plus network infrastructure exceptions below. |
| `hosts` | DNS names, IP addresses, or CIDRs. A blocklist must not be empty. An empty allowlist blocks all non-exempt outbound destinations. |
| `timezone` | Optional IANA timezone, such as `Europe/Rome` or `America/New_York`. Omitted or `Local` uses the machine's local timezone at daemon startup. Use an explicit timezone for predictable travel behavior. |
| `schedules` | Optional array. Omit or use `[]` for manual sessions only. |

DNS names also include their `www.` variant. Other subdomains must be listed explicitly. Use ASCII/Punycode names; URLs, paths, ports, wildcard domains, and scoped IPv6 addresses are not supported. Hostnames are normalized to lowercase; CIDRs are masked to their network boundary.

An allowlist example:

```json
{
  "mode": "allowlist",
  "hosts": ["example.com"],
  "timezone": "UTC",
  "schedules": []
}
```

Websites often depend on additional API, authentication, and CDN domains. Add these explicitly; the daemon does not scrape sites or silently expand the allowlist.

### Weekly schedules

Each schedule needs a unique `id`: 1–64 ASCII letters, digits, underscores, or hyphens, beginning with a letter or digit.

- `days`: one or more lowercase `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun`.
- `start`, `end`: `HH:MM` or `HH:MM:SS`.
- `enabled`: optional; defaults to `true`.

Days refer to the **start day**. If `end <= start`, the session ends on the next calendar day. Equal clocks mean a full local calendar day, not a zero-length session.

DST uses civil time, not fixed 24-hour arithmetic. A nonexistent clock time advances to the first valid instant after the clock gap. An ambiguous start uses the earliest occurrence; an ambiguous end uses the latest. A whole skipped date whose start and end collapse produces no session.

### One-time schedules

Use RFC3339 timestamps with explicit offsets instead of `days`, `start`, and `end`:

```json
{
  "mode": "blocklist",
  "hosts": ["example.com"],
  "schedules": [
    {
      "id": "writing-2027-01-15",
      "from": "2027-01-15T09:00:00+01:00",
      "until": "2027-01-15T11:30:00+01:00"
    }
  ]
}
```

An occurrence is consumed once. Reusing a completed one-time schedule's ID does not create another session; use a new ID for a new event. Weekly occurrences are identified by schedule ID and starting civil date.

### Reload, overlap, and sleep

`reload` changes the accepted configuration for future sessions. It first records any schedule already active under the old configuration, then evaluates the new configuration. A newly enabled schedule whose time window includes now starts immediately. Removing or editing a running schedule cannot change its captured policy or end time.

Overlapping policies combine restrictively: blocklists form a union, and allowlists intersect. A manual break does not suspend a scheduled policy.

The daemon evaluates schedules every second and on startup. Waking or booting inside a schedule activates its remaining window; a window entirely missed while powered off is not replayed. Manual session deadlines continue through sleep and power-off. Reboot recovery is implemented through persisted state and launchd; enforcement cannot run while macOS is not running.

## Enforcement and limits

The daemon manages only its own `/etc/hosts` section and PF anchor, `com.apple/000.lockin`. It does not rewrite `/etc/pf.conf`, replace other services' anchors, or globally disable PF. If the running filter ruleset is empty, it installs the standard `com.apple/*` anchor hook using a filter-only load. A nonempty incompatible ruleset is rejected rather than overwritten.

- Blocklists use hosts entries plus resolved IPv4/IPv6 destinations, including existing connections and UDP/QUIC traffic.
- Allowlist changes may flush PF's **global connection-state table** to stop already-established unlisted connections. This can interrupt other network connections; their firewall rules are not removed.
- Loopback is excluded. Allowlists permit outbound TCP/UDP destination port 53, IPv4 DHCP 68→67, DHCPv6 546→547, and ICMPv6 neighbor/router discovery types 133–136. These infrastructure exceptions can take precedence over later PF rules for those packets.
- DNS is refreshed during reconciliation, normally every 30 seconds. Previously resolved blocked addresses are retained conservatively across DNS failures and restarts. Shared/CDN IPs can cause collateral blocking of unrelated domains.
- DNS lookups use the default resolver in `resolv.conf`, not macOS's complete scoped/split-DNS routing. VPN and enterprise DNS setups may need explicit IP entries.
- A degraded DNS/firewall operation is reported as an error; available restrictive rules are retained rather than silently claiming success. A failed `start` can still leave a durably recorded session: inspect `status` before retrying.

This is a focus tool, **not a security boundary against an administrator**. Root can change firewall rules, state, the clock, or the daemon. Forward clock changes can expire sessions. Proxies, VPN encapsulation, DNS tunnels, alternate addresses, and unlisted subdomains can bypass destination-based filtering. No claim of universal website blocking or privileged-tamper resistance is made.

## Files and operations

| Path | Purpose |
| --- | --- |
| `~/.config/lockin/config.json` | Editable configuration used by `check` and `reload`. |
| `/usr/local/bin/lockin` | Installed native executable. |
| `/Library/LaunchDaemons/local.lockin.daemon.plist` | Root daemon, automatically restarted by launchd. |
| `/var/db/lockin/` | Root-only session state, firewall recovery data, and `daemon.log`. |
| `/var/run/lockin/control.sock` | Control socket accessible only to the installed owner UID and root. |

The daemon starts from its **last accepted, durable configuration**, not unsubmitted edits to the user file. Always run `lockin reload` after editing. Only the installed owner's account can control it without root.

For diagnostics:

```sh
lockin status --json
sudo cat /var/db/lockin/daemon.log
launchctl print system/local.lockin.daemon
```

For an upgrade, pull the new source and rerun `./install.sh`. Installation replaces the binary and restarts launchd while preserving existing sessions and accepted configuration. It does not use reinstalling as a way to reset a session.

## Development

```sh
go build -o lockin .
go test -race ./...
go vet ./...
```

The implementation is split by responsibility:

- `config.go`: strict configuration validation and duration parsing.
- `engine.go`: deterministic schedule/session transitions with immutable active policies.
- `daemon.go`: single-owner control loop, atomic state persistence, Unix socket.
- `firewall.go`: macOS PF, DNS resolution, hosts preservation, failure recovery.
- `main.go`, `install.go`: command-line interface and launchd installation.

Regression tests cover DST gaps/folds, overnight/overlapping schedules, reload and restart invariants, emergency-use persistence, persistence failures, network-policy intersection, and preservation of unrelated hosts entries. Privileged live verification is separate from the normal test suite because it changes the machine's actual networking.
