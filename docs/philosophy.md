# Design Philosophy

This document governs **how technical decisions are made**. Process rules — who decides, evidence discipline, release gates — are in `governance.md`. Document form is in `authoring.md`. The product contract is the blueprint.

Philosophy does not track releases, so nothing here carries a version number. It sits upstream of the blueprint: **when a blueprint clause and this document disagree, the blueprint is what changes.**

This file is the source of truth and is written in English, which is a deliberate exception to AUTH-6. The reason is in PHIL-4 below: a hand-maintained translation is a second copy of the same facts with no mechanism keeping them in sync, and it will drift.

---

## PHIL-0 What Flux-rs is

A root module that sends **the traffic of apps you picked** through an unmodified official sing-box, by classifying packets in the kernel on socket UID. It does not create a VPN, does not rewrite addresses or ports, and does not touch traffic from apps you did not pick.

Three things follow from that sentence, and they are the reason most of the principles below exist:

- **It shares the device with Android.** netd, the vendor's own BPF programs, and the user's other modules were there first. Flux owns a small set of objects with exact identities and nothing else.
- **Failure is visible to the user as "my phone has no internet."** That raises the cost of a wrong guess far above the cost of refusing to start.
- **The user has root.** They can do anything to their own device. Flux is not in a position to protect them from themselves, and should not pretend to be.

### What it refuses to be

Not a proxy implementation, not a router, not a rule engine. sing-box does all of that and does it better. Flux answers exactly one question — *does this packet belong to a selected app* — and hands the packet over with its original destination intact. Every proposal that widens that question should be read as a proposal to become a different product.

---

## PHIL-1 Mechanism is not policy

**Rule:** things the mechanism requires in order to work belong to Flux; things the user is trading off belong to the user. They do not share a data structure and they are not governed by the same switches.

### Test

For every knob the user can see, ask: **what happens if they get it wrong?**

| Answer | Verdict |
|---|---|
| "They get a different behaviour, which is what they asked for" | Policy. Expose it. |
| "The mechanism breaks" — self-loop, port collision, nothing is captured | Mechanism. Do not expose it. |

### Corollary: the number of guards is a negative quality metric

When two designs reach the same goal, count the validations each needs. The one needing six is usually the one that put an internal invariant in a user-editable file. **Six guards are not rigour; they are design debt handed to the validator.**

Pulling the value back inside removes all six at once. It does not turn them into six better guards.

### Evidence

`AndroidTProxyShell/tproxy.sh:980-1012` orders its chains with numbered comments: conntrack REPLY bypass first (to preserve netd's marks and survive strict RPF), then the core's own bypass, and only then reserved ranges and user policy. Mechanism precedes policy, and the failure log for the mechanism half is `"Core traffic bypass not configured, may cause traffic loop"`.

`box4magisk/box/scripts/net.inotify:15-22` inserts the device's own addresses into `BYPASS_IP` as an *anti-loopback rule*, on a separate path from the user's `cn.zone` list. Same distinction, made by a different project, independently.

This project has already made the split once without naming it: D20 moved local addresses out of the bypass LPM into a dedicated `self_addr_*` hash. The stated reason was that full-length prefixes waste a trie, but the real reason is that they are a different kind of thing. `bpf/flux.bpf.c:420-439` is therefore already two-tier.

### This rules out

- Letting the user configure the listener address, the veth names, TC handle numbers, or map names.
- Mixing reserved ranges and user preferences in one set that a `mode` flag can invert.
- Using "check that the user did not get it wrong" where "the user cannot express it wrong" was available.

---

## PHIL-2 Prefer unrepresentable over checked

**Rule:** before adding a validation, try to make the invalid state impossible to construct.

This is the constructive form of PHIL-1's corollary. Counting guards tells you a design is wrong; this tells you what to do instead.

### Test

For each error the code checks for, ask: **could a type, a generated value, or a different ownership boundary have made this error unwriteable?**

Rust makes this cheap in ways that shell projects cannot reach, which is most of why the rewrite was worth doing. A parsed `Ipv4Cidr` that is canonical by construction needs no "is it canonical" check at every use. A port that Flux draws and never exposes needs no "is the port valid" check.

### Evidence, including the counter-example

Vector chose the opposite in one place and documented why: a malformed `module.prop` must not make an entire module invisible, so it parses defensively rather than refusing (`daemon/.../FileSystem.kt:255-257`). That is correct **there**, because the input is third-party data outside their control.

The distinction is ownership. Data we generate should be unrepresentable-when-invalid. Data that arrives from outside — user configs, other modules' files, kernel dumps — must be parsed defensively, because we do not control its producer.

### This rules out

- Validating a value that Flux itself produced.
- "Defensive" checks on internal invariants, which hide the fact that the invariant is not enforced structurally.

---

## PHIL-3 Subscribe, never poll

**Rule:** every periodic wakeup must be able to name the event it is waiting for. If it cannot, it is polling.

### Test

Look at a timer and ask: **what state does it query when it fires?**

| Behaviour | Verdict |
|---|---|
| Queries state to decide what to do | Polling. Forbidden. |
| Performs an action the user explicitly configured, querying nothing | Not polling. A 24-hour subscription refresh is this. |
| One-shot, deadline-bounded, cancelled on success | Not polling. Engine listener readiness is this, capped at 250 ms / 5 s. |

### Evidence

`box4magisk/box4_service.sh:27` states the principle and its own compromise in one comment:

> `#Use inotifyd to monitor write events in the /data/misc/net directory for network changes, perhaps we have a better choice of files to monitor (the /proc filesystem is unsupported) and cyclic polling is a bad solution`

NeoZygisk describes its monitor as a *"single-threaded, event-driven application"* built on `epoll` plus `signalfd` (`loader/src/ptracer/monitor.hpp:21-22`), reserving `poll(…, 0)` for non-blocking liveness probes.

Flux already has six event sources on one epoll: signalfd, inotify, rtnetlink, pidfd, the BPF fault ring buffer, and timerfd. The capability is present; what is usually missing is wiring an existing event to a behaviour the user can feel.

### This rules out

- Health probes, periodic `SOCK_DIAG` sweeps, network watchdogs.
- Fixed-interval retry where "retry when the network comes back" was available.
- Re-dumping topology on a timer "to be safe".

---

## PHIL-4 One source of truth; everything else must be rebuildable

**Rule:** a fact has exactly one writable home. Everything else is derived, and a derived artifact must be reconstructible from its sources.

### Test

**How many places can change this fact?** More than one and it will diverge; only the timing is unknown.

**If I delete this artifact, can it be rebuilt?** If not, it is not derived — it is a second truth.

### Evidence

Vector recorded a real bug rather than a theory (`daemon/.../ModuleDatabase.kt:28-31`): `enabledModules()` read the cache, so the manager enabled a module, read back immediately, and was told the state from before its own write. Their fix was not a lock; it was writing the boundary down (`manager/README.md:54-55`):

> *"The daemon owns the truth. When a write and a read disagree, the read is usually coming from the daemon's asynchronous cache."*

In this project: the on/off switch is the root manager's own `disable` file and nothing else; the version lives only in the workspace manifest and `module.prop` is generated from it; the `description=` line is a projection of state, never a source of it.

### This rules out

- A second toggle (an `enabled` key in config, a bit remembered by a script).
- Reading a cache where the truth was required.
- Hand-maintained translations of a normative document.

---

## PHIL-5 Ownership is proven, not remembered

**Rule:** before deleting any kernel object, prove from the kernel — right now — that it is ours. Never from a file recording what we created.

### Test

**If that record were lost, could cleanup still be safe?** If not, ownership rests on bookkeeping rather than identity.

### Evidence

`AndroidTProxyShell/tproxy.sh:250-277` writes a `runtime_tproxy.conf` snapshot at start and reads it at stop (`:1627-1633`). When the snapshot is missing, stop falls back to the *current* config and may delete rules it does not own. `box4magisk` goes further: `uninstall.sh:3` removes only the `service.d` hook and leaves the iptables rules in place.

The good counter-example is `bpfmatcher`, whose `--stop` unlinks exactly the four paths named in the policy and nothing else (`README.md:61`, `bpf-matcher.c:628-637`).

Flux matches on the full identity — netns, ifindex, ifname, parent, chain, preference, handle, protocol, kind, direct-action, program name, map set — and dumps the plan twice, refusing to proceed if the two dumps differ.

### This rules out

- Flushing a qdisc or a chain.
- Deciding what to delete from a PID file or a state file.
- Deleting anything because it "looks like ours".

---

## PHIL-6 Fail hard only when failure is silent

**Rule:** refuse to start only when the failure would be both silent and undiagnosable. Everything else warns loudly and proceeds.

### Test

**Can the user follow the symptom back to the cause?**

- Yes → warn and proceed. It is their device and they have root.
- No → refuse, and say the cause in the error itself.

### Evidence

A positive case and a negative one, both measured.

The positive case is a fakeip range overlapping the bypass set (D21). The symptom is "DNS resolves, the app connects, nothing loads," and no log line points at the cause. That must be refused.

The negative case is `AndroidTProxyShell/tproxy.sh:1010-1011`, which logs one error when the core's own bypass could not be configured and continues. The consequence is a traffic loop — **also undiagnosable**. That one should have refused and did not.

On the other side: an empty `clash_api` secret is diagnosable, because any app on the device can reach the control port and the user finds out by trying. That belongs in the warn column. Flux is a root module; deciding security trade-offs on the user's behalf is not part of the product.

### This rules out

- Refusing an operation "for safety" when the user is root and the outcome is visible.
- Its mirror image: waving through an undiagnosable failure in the name of user freedom.

---

## PHIL-7 Shell installs; the binary runs

**Rule:** module scripts verify the payload, set permissions, and start a process. Anything whose behaviour depends on runtime state lives in Rust.

### Test

**Does this script's behaviour change with the state of the running system?** If yes, it belongs in the binary.

### Evidence

Two independent high-star projects agree. Vector's `service.sh` is six lines — unshare, then start the daemon — and its `customize.sh` does SHA-256 verification, ABI extraction and permissions, with no runtime logic. NeoZygisk's `action.sh` is a single `cat` of a status file the monitor maintains.

### This rules out

- Convergence decisions in `service.sh`.
- Shell parsing state to choose which command to run.

---

## PHIL-8 Method: how to use reference implementations

Not a design principle — a rule for reading the projects listed in `tools/clone-manifest.md`.

**Take the principle, not the workaround.** For each practice worth copying, ask: *would they still do it this way if they had our tools?*

`box4magisk` watches `/data/misc/net` to detect network changes and says in the comment that `/proc` cannot be inotified. They are approximating netlink with file watching because shell cannot reach netlink. What is worth inheriting is `cyclic polling is a bad solution`, not the directory path.

Likewise `Flux-original/updater.sh:175-245` hand-writes a base64 decoder, a URL decoder and a JSON field extractor in awk. All three are library calls in Rust, and every hand-rolled version is a source of bugs. Inherit the pipeline shape — fetch, decode, refine, apply template, validate, replace atomically — not the implementation.

The converse also holds: being a Rust project is not a reason to skip reading shell projects. Their design judgments were paid for with real devices.

---

## PHIL-9 What this does not forbid

Principles without boundaries become dogma. None of the following is a violation:

| Looks like a violation | Why it is not |
|---|---|
| A 24-hour subscription refresh timer | Queries no state; performs a configured action (PHIL-3) |
| Bounded re-checks while an engine candidate starts | One-shot, deadline-bounded, cancelled on success |
| Generated output containing things the user did not write | Derived artifacts are built from several inputs; what matters is that they can be rebuilt (PHIL-4) |
| The user being able to **see** an internal value | PHIL-1 forbids editing, not seeing. `run/sing-box.<gen>.json` is on disk and complete |
| Verification logic in an install script | PHIL-7 excludes runtime logic, not install-time I/O |
| Keeping a cache | PHIL-4 requires caches to be rebuildable, not absent |
| Defensive parsing of user configs or kernel dumps | PHIL-2 applies to data we produce, not data we receive |

---

## PHIL-10 Review checklist

Before writing code, answer these. Not being able to answer one is the finding.

1. Does this put an internal invariant somewhere external? (PHIL-1)
2. How many guards does it need, and is there a zero-guard alternative? (PHIL-1, PHIL-2)
3. Could a type or a generated value make the error unwriteable? (PHIL-2)
4. Does it add a periodic wakeup, and what does that wakeup query? (PHIL-3)
5. How many places can write this fact, and can the derived copies be rebuilt? (PHIL-4)
6. Does deletion rest on identity or on bookkeeping? (PHIL-5)
7. For each hard failure: is it genuinely undiagnosable? (PHIL-6)
8. Is anything taken from a reference implementation a principle or a workaround?

Consequences for the current codebase are tracked in `plan/implementation.md`, not here — a dated list of pending work does not belong in a document that is supposed to outlive it (PHIL-4).

---

## PHIL-11 Amending this document

It can be overturned, through the correction protocol in GOV-3: record the original claim, what was actually observed, and the disposition. State **which test failed**, not that the situation was special. "This case is different" is how a philosophy becomes decoration.
