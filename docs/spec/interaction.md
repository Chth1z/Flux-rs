# Part 27: Interaction Contract

> **Normative contract.** If the implementation disagrees with this document, the implementation is wrong. Reader-facing material lives in three places: [`../guide/introduction.md`](../guide/introduction.md) explains what this is and where its boundaries are (for users), [`../guide/architecture.md`](../guide/architecture.md) explains why it has this shape (for implementers), and [`../guide/how-to.md`](../guide/how-to.md) explains how to install and configure it and what to do when something goes wrong.
>
> §27 opens a new part after the 0.9.0 numbering space. These clauses previously lived in `docs/ux.md` under that document's own §1–§8 numbering, which conflicted with the blueprint's §1–§8—`rg "§3"` returned two unrelated things, so every reference required a filename to disambiguate it. That violated the global stable-numbering rule of AUTH-1.1, so the split folded these clauses into the global numbering.

## 27.1 The switch is the manager's own module switch

### 27.1.1 One source of truth

```text
/data/adb/modules/flux_rs/disable
present = desired disabled (MAY briefly be Inactive during convergence; Disabled on completion)
absent = desired enabled (then MAY be Inactive or Active)
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
description=Transparent per-app proxying via eBPF and an unmodified official sing-box.\n🥰 [Active] gen 7 · 3 apps · rmnet_data0
```

`\n` is the literal two-character escape, which the manager renders as a line break; the first line is always the original description. Rules:

| State | Display |
|---|---|
| Active | `🥰 [Active] gen N · X apps · <active interfaces>` |
| Inactive, with a concrete error | `🤯 [Inactive] <stable error token>` |
| Inactive, converging | `🤔 [Inactive] converging` |
| Disabled, engine stopped | `😴 [Disabled] toggle this module on to enable Flux` |
| Disabled, engine still terminating | `😴 [Disabled] stopping` |

Three implementation constraints: compare before writing and do not write when the state is unchanged; atomically replace the file using a temporary file in the same directory plus `rename`, so the manager always reads a complete file; rewriting MUST be idempotent, so repeated writes never cause `description=` to grow without bound. A write failure only removes the status display and MUST NOT affect the daemon—`module.prop` belongs to the manager.

---

## 27.2 Configuration

### 27.2.1 Paths and ownership

```text
/data/adb/modules/flux_rs/
├── disable                          Manager-owned; the only switch (§27.1.1)
└── webroot/index.html               Redirect shell for the manager's button (§28.8)

/data/adb/flux-rs/
├── config/                          User authority; Flux MUST NOT write back to it
│   ├── flux.toml
│   ├── template.json
│   └── *.txt                        List files referenced with @ (§27.2.2)
├── fluxd.log
└── run/                             Machine output; MAY be deleted and rebuilt at any time
    ├── daemon.lock
    ├── control.sock
    ├── subscription.raw
    └── sing-box.<generation>.json
```

**There is no `disable` under the state root.** There is exactly one switch, in the module directory, created and deleted by the root manager.

**Everything under `config/` is yours; nothing under `run/` is.** This boundary is the entire configuration model:

- `config/flux.toml`: which apps are selected, which destinations are Direct, which interfaces are used, and subscription parameters;
- `config/template.json`: the sing-box configuration template—the DNS, routing rules, and selector skeleton. **This is what you edit**, not the file the engine actually runs;
- `run/sing-box.<gen>.json`: generated from the template + raw subscription, one read-only file per generation, deleted when the generation changes.

Flux MUST NOT write any file under `config/`. Installation or upgrade copies `etc/default-flux.toml` and `etc/default-template.json` only when the corresponding file is missing.

See §28 for generation rules, the subscription pipeline, and failure handling; **this section describes only the boundary and does not repeat that algorithm**.

### 27.2.2 The only `flux.toml` schema

Every dimension has the same shape: a mode and a list. The full schema and the
reasoning behind it are §11.2; this section states the user-visible contract.

```toml
[apps]
# whitelist = proxy only what is listed; blacklist = proxy everything except
# Format: userId:packageName. A shared UID also captures packages with that UID.
mode = "whitelist"
list = ["0:com.example.browser", "@apps.txt"]

[cidr]
# blacklist = listed destinations go Direct (the ordinary use)
# whitelist = capture only the listed destinations
mode = "blacklist"
list = ["192.168.0.0/16", "@chnroute.txt"]

[interfaces]
# blacklist with an empty list = take over every supported physical interface
mode = "blacklist"
list = []

[ssid]
# blacklist = do not activate on a listed Wi-Fi network
mode = "blacklist"
list = []

[subscription]
url = ""            # empty disables subscription entirely; no fetch, no timer
interval = 86400    # seconds; 0 = manual only
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

The packaged path is `etc/default-template.json`; the repository source is `module/template.json`; the installed device path is `config/template.json`. It comes from the original Flux `conf/template.json`, so both projects present the same shape to users: DNS splitting and fakeip, `clash_mode` rules, remote rule-sets, and `PROXY`/`GLOBAL` selectors.

Four properties MUST hold for the defaults (`cargo xtask template-check` checks each one and then runs one real `check` with the official sing-box):

| Constraint | Why |
|---|---|
| No `inbounds` | Flux injects two tproxy inbounds at runtime; a template inbound would compete for their listeners |
| No `experimental.clash_api` | The default opens no control port; §27.2.4 defines the rules when users open one themselves |
| Every selector/urltest has at least one member | An empty selector cannot resolve, causing `check` to fail before the user has edited anything |
| fakeip ranges avoid the fixed bypasses | Flux unconditionally bypasses the entire ULA `fc00::/7`; a fakeip inside it is sent Direct, silently breaking all IPv6 fakeip. Determine containment from parsed prefixes and `flux_core::cidr::fixed_bypass`, not string prefixes—both `fd00::/8` and `FD00::/8` MUST be rejected |

The template ships with no server, no subscription and no credential: `PROXY`
initially points only at `DIRECT`.

**The user edits this template; they do not replace it with a finished config.**
Flux generates `run/sing-box.<generation>.json` from the template plus the
subscription (§28), filling empty selector groups and appending refined nodes.
Everything else in the template passes through byte for byte, so what the user
writes is what the engine runs.

### 27.2.4 Optional `clash_api`

Flux packages no WebUI and manages no zashboard. `webroot/index.html` is a
twelve-line redirect to whatever controller the user configured, carrying the
secret so it need not be typed (§28.8); when no `clash_api` is configured the
page says so rather than redirecting into a connection failure.

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
| `fluxd daemon` | Foreground reactor; `start` and `run` are aliases |
| `fluxd status [--json]` | Human-readable or raw JSON status |
| `fluxd check` | Read-only validation of configuration, package resolution, and engine configuration |
| `fluxd enable` | Delete the module-directory `disable` and request convergence |
| `fluxd disable` | Create `disable`, publish inactive, and stop the engine |
| `fluxd reload` | Process the policy and engine candidate separately |
| `fluxd stop` | Publish inactive, stop the child, and exit the daemon |
| `fluxd bugreport` | Generate a diagnostic ZIP |
| `fluxd version` | Version, ABI magic, and build information |
| `fluxd subscribe` | Fetch the subscription once and rotate if the result differs (§28.7) |

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

---

## 27.4 Diagnostic bundle

By default, `fluxd bugreport` generates a redacted ZIP:

- Includes status, version/ABI, root manager, a limited log tail, network/BPF enumeration, and configuration shape;
- Does not include raw `flux.toml`, `template.json`, or generated `sing-box.<gen>.json`;
- Applies stable redaction to sensitive address and interface values by default;
- Excludes logcat by default; only `--with-logcat` explicitly includes it and emits a warning;
- `--raw` disables address redaction and emits a warning;
- `-o <dir>` selects the output directory.

The diagnostic bundle MUST NOT claim "cleaned" unless a fresh actual enumeration proves that the objects are absent.

---

## 27.5 First use

A fresh install follows this deterministic order:

1. The installer creates the state root and the two missing bootstrap configuration files;
2. It creates `disable` in the module directory, so **the module appears off in the manager immediately after installation**, and installation itself captures no traffic;
3. The user edits `config/flux.toml` and `config/template.json`;
4. Run `fluxd check`;
5. After the check passes, enable the module in the manager (or run `fluxd enable`; both write the same file);
6. Use `fluxd status` or the description in the manager's module list to confirm the engine and per-interface coverage.

The installer MUST explain step 2 clearly; otherwise users will mistake "shown as disabled after installation" for an installation failure. An upgrade does not recreate this file: an enabled module remains enabled.

**The initial enablement in step 5 requires one reboot.** A disabled module does not execute `service.sh`, so no daemon is yet listening for the switch; immediate effect requires the daemon to already be running. Every subsequent toggle takes effect immediately.

```sh
FLUXD=/data/adb/modules/flux_rs/bin/fluxd
$FLUXD check
$FLUXD enable      # Equivalent to enabling the module in the manager
$FLUXD status
```

If there are no selected apps, the configuration MAY still be valid, but status MUST explicitly show selected=0; it MUST NOT describe the state as "proxied."

---
