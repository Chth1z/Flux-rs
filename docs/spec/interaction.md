# Part 27: Interaction Contract

> **Normative contract.** If the implementation disagrees with this document, the implementation is wrong. Reader-facing material lives in three places: [`../guide/introduction.md`](../guide/introduction.md) explains what this is and where its boundaries are (for users), [`../guide/architecture.md`](../guide/architecture.md) explains why it has this shape (for implementers), and [`../guide/how-to.md`](../guide/how-to.md) explains how to install and configure it and what to do when something goes wrong.
>
> §27 opens a new part after the 0.9.0 numbering space. These clauses previously lived in `docs/ux.md` under that document's own §1–§8 numbering, which conflicted with the blueprint's §1–§8—`rg "§3"` returned two unrelated things, so every reference required a filename to disambiguate it. That violated the global stable-numbering rule of AUTH-1.1, so the split folded these clauses into the global numbering.

## 27.1 The switch is the manager's own module switch

### 27.1.1 One source of truth

```text
/data/adb/modules/Flux-rs/disable
present     = desired disabled (MAY briefly be Inactive during convergence; Disabled on completion)
absent      = desired enabled (then MAY be Inactive or Active)
unreadable  = not enabled: capture MUST NOT start; `status` reports the observation failure
```

**This is the same file that Magisk / KernelSU / APatch creates and deletes when you toggle the module switch.** Flux no longer maintains a second switch: `/data/adb/flux-rs/disable` does not exist, and `flux.toml` has no `enabled` key.

`fluxd` watches the module directory with the existing inotify source:

- File appears: first publish `active=0`, then stop the engine; the daemon remains in the event loop and waits;
- File disappears: reread the authority files and converge.

The result is that **turning off the module in the manager takes effect immediately, without a reboot**. The manager's original semantics—do not load it on the next boot—remain intact; Flux also gives the switch effect during the current boot.

`fluxd enable` / `fluxd disable` write the same file, so the command line and manager UI always agree; there is no state in which "the command line says enabled while the manager shows disabled."

"Disable immediately" means immediately stop admitting new flows and terminate the engine. It does not mean immediately detach TC or delete veth/rule/route/map objects. Keeping those objects avoids accidentally deleting system state on stop/uninstall paths; non-persistent objects disappear naturally after a device reboot.

### 27.1.2 Flux touches only two files in the module directory

The module directory belongs to the manager. Flux writes only `disable` and the `description=` line in `module.prop`; it MUST NOT create, move, or delete this directory, and it does not modify any other key in `module.prop`.

### 27.1.3 `module.prop` is a status display

There is no `action.sh`—the switch is the manager's own switch, so there is no need for a second button and no dependency on Magisk v28+ Action support.

In exchange, `fluxd` writes the current state to `description=` in `module.prop`, turning the manager's module list into a status panel:

```text
description=Seamlessly redirect your network Flux.\n🥰 [RUNNING] PID: 1234 · 黑名单 · 排除清单 3 项 · wlan0
```

`\n` is the literal two-character escape, which the manager renders as a line break; the first line is always the original description. That first line is written for the person reading a module list, not for a reviewer: it says what the module does for them and MUST NOT carry a positioning statement ("unmodified", "official", "eBPF") or overstate the failure semantics of §2.2. Rules:

| State | Display |
|---|---|
| Active | `🥰 [RUNNING] PID: N · <app mode and list meaning> · <active interfaces>` |
| Inactive, with a concrete error | `🤯 [FAILED] <stable error token>` |
| Inactive, converging | `🤔 [STARTING] 正在应用配置` |
| Inactive, paused by `[ssid]` on the current Wi-Fi network (§29.5) | `😴 [PAUSED] 当前 Wi-Fi 不符合启用条件` — never the network's name |
| Disabled, engine stopped | `😴 [STOPPED] 已停用` |
| Disabled, engine still terminating | `🤔 [STOPPING] 正在停止` |

These labels project the existing three-state model; they do not create another
state machine. RUNNING requires the Active evidence of §10.1, not merely a live
PID, and makes no claim about Internet reachability. Whitelist mode renders
`白名单 · 选择清单 N 项`; blacklist renders `黑名单 · 排除清单 N 项`. N counts
expanded configuration entries, not selected UIDs or every package sharing a
UID. Actual selection and draining counts remain available from `status`.
An Active generation with a rejected update keeps RUNNING and adds the update's
stable error token. Generation identifiers belong in detailed diagnostics.

Three implementation constraints: compare before writing and do not write when the state is unchanged; atomically replace the file using a temporary file in the same directory plus `rename`, so the manager always reads a complete file; rewriting MUST be idempotent, so repeated writes never cause `description=` to grow without bound. A write failure only removes the status display and MUST NOT affect the daemon—`module.prop` belongs to the manager.

---

## 27.2 Configuration

### 27.2.1 Paths and ownership

```text
/data/adb/modules/Flux-rs/
├── disable                          Manager-owned; the only switch (§27.1.1)
└── webroot/index.html               Redirect shell for the manager's button (§28.8)

/data/adb/flux-rs/
├── config/                          User authority; the running daemon is read-only
│   ├── flux.toml
│   ├── advanced.toml                 Optional; absent means built-in defaults
│   ├── template.json
│   └── *.txt                        List files referenced with @ (§27.2.2)
└── run/                             Persistent machine-managed data
    ├── fluxd.log                     Current log; numbered retained files beside it
    ├── daemon.lock
    ├── control.sock
    ├── cache/
    │   ├── sing-box.db               Default engine cache
    │   └── sources/<source-id>.raw   Accepted remote responses
    ├── migrations/                  Exact input backups when an upgrade changes schema
    └── sing-box.<generation>.json
```

**There is no `disable` under the state root.** There is exactly one switch, in the module directory, created and deleted by the root manager.

**Everything under `config/` is yours; nothing under `run/` is.** This boundary is the entire configuration model:

- `config/flux.toml`: which apps are selected, which destinations are Direct, which interfaces are used, and where nodes come from;
- `config/advanced.toml`: fetch, refinement, group matching and log retention (§11.2.4), with no duplicate fields or override order between files;
- `config/template.json`: the sing-box configuration template—the DNS, routing rules, and selector skeleton. **This is what you edit**, not the file the engine actually runs;
- `run/sing-box.<gen>.json`: generated from the template + raw subscription, one read-only file per generation, deleted when the generation changes.

The running daemon MUST NOT write any file under `config/`. Installation copies
missing bootstrap files and performs only the explicit schema migration of
§13.2.3. The template is always preserved. An absent advanced file uses built-in
defaults; the packaged advanced example documents optional settings. Missing
main configuration is an error, distinct from an explicitly empty valid file.

`run/` is not wiped at boot or upgrade. Its caches support offline reconstruction;
its socket and lock must remain intact while the daemon is alive. Explicit
user-supplied engine paths retain their native meaning (§9.6); Flux-managed
default outputs stay under `run/`.

See §28 for generation rules, the subscription pipeline, and failure handling; **this section describes only the boundary and does not repeat that algorithm**.

### 27.2.2 The only `flux.toml` schema

Every traffic-selection dimension has the same shape: a mode and a list. The
full main and advanced schemas are §11.2 and §11.2.4; this section states the
user-visible contract. The minimal main configuration is:

```toml
[apps]
mode = "blacklist"
list = []

[nodes]
sources = []        # HTTP(S) subscriptions, sharing URIs and/or @nodes.txt
```

Rules:

- Unknown keys are rejected, with the closest valid key reported.
- Packages and CIDRs MUST be canonical, deduplicated and within capacity.
- A missing package, or a shared-UID expansion, MUST be shown explicitly by
  `check`.
- A list entry beginning with `@` names a file inside `config/`, one entry per
  line, `#` starting a comment. **Whether an entry is a path is decided by the
  leading `@` alone** — never by testing whether it parses as a CIDR, which
  would turn one mistyped CIDR into a silent filename.
- `mode = "blacklist"` with an empty list is the automatic mode. There is no
  third enum value, because a state reachable two ways drifts.
- **`status` MUST print the mode in force, not merely the entry count.** In
  whitelist mode a single mistyped entry sends everything Direct, silently.
- There is no `apps`, `bypass_cidrs`, `bypass_v4`, `bypass_v6`, `bypass.files`
  or `enabled` key.

### 27.2.3 Bootstrap engine configuration

The packaged path is `etc/default-template.json`; the repository source is `module/template.json`; the installed device path is `config/template.json`. The default retains the original DNS splitting, fakeip, `clash_mode`, rule-sets and outbound menus: `PROXY` selects `HK`/`TW`/`JP`/`SG`/`US`, and `GLOBAL` selects `PROXY`. Adding a node source MUST NOT rewrite these menus.

Four properties MUST hold for the defaults (`cargo xtask template-check` checks each one and then runs one real `check` with the official sing-box):

| Constraint | Why |
|---|---|
| No `inbounds` | Flux injects two tproxy inbounds at runtime; a template inbound would compete for their listeners |
| No **active** `experimental.clash_api` | The default opens no control port. The original's block is carried in the file **commented out**, so the panel is discoverable without being enabled behind the user's back; §27.2.4 defines the rules once they uncomment it |
| The five regional groups start empty; `PROXY` and `GLOBAL` keep their written menus | Generation fills empty groups and appends nodes (§28.2); it never replaces a nonempty menu. With no nodes to fill the groups, Flux reports the incomplete candidate |
| fakeip ranges avoid the fixed bypasses | Flux unconditionally bypasses the entire ULA `fc00::/7`; a fakeip inside it is sent Direct, silently breaking all IPv6 fakeip. Determine containment from parsed prefixes and `flux_core::cidr::fixed_bypass`, not string prefixes—both `fd00::/8` and `FD00::/8` MUST be rejected |

The template ships with no server, no subscription and no credential: its five
regional groups are empty, waiting for manual nodes or a subscription (§28.2).
Until something fills them there is nothing to run, and `check` says exactly
that — `engine_config_unfilled`, naming the groups. A manual node participates
in a regional group when its name matches that region. A user can also name it
explicitly in an existing menu or add an empty `AUTO` selector to receive all
nodes. Such menu edits belong to the user. Flux never rewrites the user's
template during an upgrade.

**The user edits this template; they do not replace it with a finished config.**
Flux generates `run/sing-box.<generation>.json` from the template plus available
manual and remote nodes (§28), filling empty selector groups and appending nodes.
Everything else retains its JSON value; JSONC comments and formatting are not
part of the generated JSON. The source template remains untouched.

### 27.2.4 Optional `clash_api`

Flux packages no WebUI and manages no zashboard. `webroot/index.html` is a
single redirect page: opened from the manager's module list, it reads the
controller address and secret the user configured and navigates there, so
neither has to be typed (§28.8); when no `clash_api` is configured the page
says so rather than redirecting into a connection failure.

The template carries the original's block, commented, at the end of `experimental`, with `secret` blank and both costs of enabling it stated in place: on Android every app holding INTERNET can reach `127.0.0.1`, so an empty secret hands any of them the proxy's controls; and `external_ui_download_url` has the engine fetch and unpack a zip at run time with no digest to check it against, through the proxy, into the engine's working directory (`/data/adb/flux-rs`). Commenting rather than omitting is what keeps "the shipped default is the original's template" true: the only difference is that this block is inert until the user acts.

If a user configures `experimental.clash_api`:

- `external_controller` SHOULD listen on loopback;
- `secret` SHOULD be non-empty;
- UI downloads, TLS, updates and access control are the user's responsibility.

**`fluxd check` warns about an unsafe controller or an empty secret; it does not
refuse to start, and it never edits the configuration.** The distinction is §23's:
an unsafe control port is a diagnosable difference of intent, visible in `status`
and correctable by the user, not an undiagnosable failure. Refusing would also
make Flux the arbiter of a decision inside sing-box's own authority (§9.6).

---

## 27.3 CLI and control socket

### 27.3.1 The current command set

| Command | Behavior |
|---|---|
| `fluxd daemon` | Foreground supervisor that runs and, after a crash, restarts the reactor (§13.2.2); `start` and `run` are aliases |
| `fluxd status [--json]` | Human-readable or raw JSON status |
| `fluxd check` | Read-only validation of configuration, package resolution, and engine configuration |
| `fluxd enable` | Delete the module-directory `disable` and request convergence |
| `fluxd disable` | Create `disable`, publish inactive, and stop the engine |
| `fluxd reload` | Process the policy and engine candidate separately |
| `fluxd stop` | Publish inactive, stop the child, and exit the daemon |
| `fluxd bugreport` | Generate a diagnostic ZIP |
| `fluxd version` | Version, ABI magic, and build information |
| `fluxd subscribe` | Refresh the configured remote sources once and rotate if the combined result differs (§28.7) |

There is no `explain` and no `watch`: `status` is made complete and honest first, and an explainer built on an incomplete status would explain the wrong thing. **Documentation MUST NOT show a command that does not exist.**

### 27.3.2 Socket interface

`/data/adb/flux-rs/run/control.sock` is a root-only `SOCK_SEQPACKET` with mode 0600, carrying seven idempotent requests: `status`, `check`, `enable`, `disable`, `reload`, `stop` and `subscribe`.

Idempotence is load-bearing rather than incidental: because replaying a request produces the same result as issuing it once, the protocol needs no request-id deduplication cache (§10.3). **A new command MUST preserve that property.**

There is no separate `wire_version`. Responses already carry the product `version` and `abi_magic`, and the CLI is the only real client; a compatibility policy gets designed when a second independent client exists, not in anticipation of one.

### 27.3.3 The minimum `status` must report

Human-readable output MUST include at least:

- `Disabled | Inactive | Active`;
- generation and backoff;
- root manager/runtime mode;
- engine PID, readiness of the 4 sockets, and effective file;
- selected/draining/bypass/self-address counts;
- one line per candidate interface: name, active/excluded, entry, actual pref, reachability, and stable reason;
- when `[ssid]` has entries: whether Wi-Fi is connected and whether the dimension is pausing Flux, without the network's name (§29.5);
- current counters, warnings, hints, and the first concrete error.

`Active` requires the engine generation to be committed, `control.active=1`, and at least one physical capture interface to be active. When the last active interface disappears, the top-level state becomes `Inactive`; if only part of the coverage is lost, it remains `Active` and explains the loss in per-interface status.

In JSON, `ifaces[].pref` is the preference actually occupied by that interface's
capture filter, selected per interface (§8.5.3). **It MUST NOT be cached as a
device-wide constant** — on one device cellular and Wi-Fi can differ.

The field naming reachability is `reachable`, and it is **tri-state: absent is
not `false`**.

| Value | Meaning | Human-readable output |
|---|---|---|
| absent | No conclusion yet: `flx_verify` has no result, or the dump itself failed | `reachability unverified` |
| `true` | Liveness verification saw a packet, or an existing owned filter passed the identity and preceding-snapshot review | `reachable` |
| `false` | Definitively unreachable: chain shadowing, identity drift, or attach failure | `not reachable` |

The distinction between absent and `false` is what keeps "the user was not online
during the window" from being reported as "a vendor filter is shadowing us"
(§8.5.4). Collapsing them would make the most common benign case
indistinguishable from the failure the check exists to find.

Human-readable output uses the reachability wording throughout and **MUST NOT
contain "first applicable"** — dump position never established this, and the
earlier field name asserted that it did.

### 27.3.4 Exit codes

The process exit code is not `Response.ok`. Three outcomes stay distinct:

| Result | Typical exit | Meaning |
|---|---|---|
| Request never reached the daemon | 1 | Socket missing, timeout, or protocol error. `stop` is 0 only when `daemon.lock` is **not** held |
| Authority file updated | 0, with a warning if the runtime is not yet at the target | `enable`/`disable` wrote the C9 file; Active/Disabled may still be converging |
| Runtime at the requested target | 0 | `reload`/`subscribe`/`check`/`status` follow `Response.ok` |

`status` success is not Internet reachability. `stop` must not treat a communication failure as idempotent success while the lock is held.

---

## 27.4 Diagnostic bundle

By default, `fluxd bugreport` generates a redacted ZIP:

- Includes status, version/ABI, root manager, a limited log tail, network/BPF enumeration, and configuration shape;
- Does not include raw `flux.toml`, `advanced.toml`, node-list files, source caches, migration backups, `template.json`, or generated `sing-box.<gen>.json`;
- Applies stable redaction to sensitive address and interface values by default;
- Excludes logcat by default; only `--with-logcat` explicitly includes it and emits a warning;
- `--raw` disables address redaction and emits a warning;
- Default redaction also masks URL userinfo and query, `Authorization` /
  password / token assignments, and node tags other than the well-known
  routing names. It does not claim to anonymise arbitrary third-party text;
- Writes under `/data/adb/flux-rs/run/` unless `-o <dir>` says otherwise. The default is not the process working directory: a root shell's cwd is `/`, which is read-only. A user-specified `-o` directory is created exclusively with mode `0700`; an existing path is refused.

The diagnostic bundle MUST NOT claim "cleaned" unless a fresh actual enumeration proves that the objects are absent.

---

## 27.5 First use

A fresh install follows this deterministic order:

1. The installer creates the state root and the two missing bootstrap configuration files;
2. It creates `disable` in the module directory, so **the module appears off in the manager immediately after installation**, and installation itself captures no traffic;
3. The user edits `config/flux.toml` and `config/template.json`;
4. Enable the module in the manager (or run `fluxd enable`; both write the same file), then reboot once after the first installation;
5. The daemon assembles the available manual and remote nodes, and checks the complete generated candidate before activation (§28.6). It fetches a subscription only when one is configured. A failed fetch does not prevent an independently complete candidate from running; an incomplete or invalid first candidate stays Inactive with its reason;
6. Use `fluxd status` or the manager description to confirm the engine and per-interface coverage; use `fluxd check` for configuration and capability diagnostics.

`check` is a diagnostic command, not a prerequisite for enabling: the activation
transaction owns validation. It is read-only and cannot fetch a subscription.
Before any node source supplies nodes, the shipped template therefore reports
`engine_config_unfilled`, naming its empty groups (§27.2.3); the user need not
run and interpret that incomplete check as an installation step.

The installer MUST explain step 2 clearly; otherwise users will mistake "shown as disabled after installation" for an installation failure. An upgrade does not recreate this file: an enabled module remains enabled.

**The initial enablement in step 5 requires one reboot.** A disabled module does not execute `service.sh`, so no daemon is yet listening for the switch; immediate effect requires the daemon to already be running. Every subsequent toggle takes effect immediately.

After enabling in the manager and completing the first reboot:

```sh
FLUXD=/data/adb/modules/Flux-rs/bin/fluxd
$FLUXD status
$FLUXD check       # Configuration and capability diagnostics, when needed
```

If there are no selected apps, the configuration MAY still be valid, but status MUST explicitly show selected=0; it MUST NOT describe the state as "proxied."

---
