# Phase 0 tooling

These tools preserve the measured 0.9.0 test shapes and raw evidence. For a
0.9.1 design claim, read the frozen `docs/spec/blueprint.md` baseline and then apply
`docs/spec/blueprint-0.9.1.md`; in particular, R091-05 replaces dump-first ordering
with reachability and R091-08 uses distinct v4/v6 listener ports even though
the historical Q2 harness isolated the lookup test with one shared port.

Phase 0 is the falsification step that runs **before** implementation. Its
purpose is to break assumptions cheaply, on real hardware, while changing them
is still free. It splits in two:

| Half | What it does | Tool |
|---|---|---|
| **Observation** | Answers "what is this device actually like" | `observe.sh` (read-only) |
| **Falsification** | Answers "does the mechanism work here" — Q1–Q10 in `docs/history/phase0.md` §16.1 | the harnesses below |

## These are regression tools, not one-shot scripts

Six of the ten questions are answered (`docs/history/phase0.md` §16.5 through
§16.10). The remaining four cannot be answered before the code they test exists,
and `docs/plan/implementation.md` §17.2 assigns each one to the stage that can
actually run it.

Every harness here stays useful after its question is closed, because the answer
is a property of a device and a kernel, not a fact about the universe. Re-run
them when the thing under them changes:

| Harness | Answers | Re-run when |
|---|---|---|
| `q1-run-device.sh` | Q1 — SK_STORAGE first decision | the §7.3 algorithm changes |
| `q1-run.sh` | Q1 in a netns on a dev host, with real concurrency | you want contention that a phone will not produce |
| `q2-run-device.sh` | Q2 — 4 listener sockets, sk_lookup fields, **sk_assign succeeds** | **every engine version bump** (§9.2 requires it) |
| `q6-veth-observe.sh` | Q6 observation, OEM chains, sysctl starting point, veth lifecycle | new device; also stage 3's Q8 |
| `q9-run-device.sh` | Q9 — per-app DNS attribution (D18) | new device or Android version |
| `q10-run.sh` | Q10 — whether a vendor filter shadows us | new device |
| `loadall-product.sh` | the four product programs pass the verifier | **every change to `flux.bpf.c`** (CI does this automatically) |
| `secname-probe.sh` + `secname-load.sh` + `secname-attach.sh` | which ELF section names load *and* attach | changing a `FLUX_SEC_*` |
| `btf-inspect.sh` | why libbpf cannot size a map from BTF | libbpf says "can't determine value size" |
| `wsl-capability.sh` | whether the build host can compile BPF at all | new development machine |
| `observe.sh` | everything about an unfamiliar device | first thing on any new device |

### How to run one

They all follow the same shape, and all of them clean up after themselves on
every exit path including SIGINT:

```bash
# compile the probe on the build host (WSL is fine)
wsl -u root bash -c "cd /mnt/d/Github/Flux-rs && \
  clang -target bpf -O2 -g -mcpu=v3 -I bpf/include \
  -I /usr/include/x86_64-linux-gnu \
  -c tools/phase0/q1_probe.bpf.c -o /tmp/q1_probe.o"

adb push /tmp/q1_probe.o /data/local/tmp/
adb push tools/phase0/q1-run-device.sh /data/local/tmp/q1.sh
adb shell "su -c 'sh /data/local/tmp/q1.sh'"
```

`-I bpf/include` is only needed by probes that include the real `flux_abi.h`,
which several deliberately do so that a pass transfers to the product rather
than to a simplified stand-in.

### Three traps these harnesses were bitten by

Worth knowing before writing the next one:

1. **`bpftool` prints BTF-typed maps as JSON with the struct's field names**, not
   as hex. A hex parser silently produces nothing. Parse the JSON, keep hex as a
   fallback.
2. **Return a negative errno through a map only in a signed type.** A `__u64`
   slot turns `-94` into a 2^64 two's complement that no shell can compare, and
   the harness then reports a perfectly good result as a failure.
3. **`ip netns exec` hides bpffs**, so a pinned program is invisible inside the
   namespace. Use `nsenter --net=...` instead, which keeps the mount namespace.

## `observe.sh`

Strictly read-only. Writes nothing, loads nothing, attaches nothing: every
command either reads a file or asks the kernel to describe existing state. Safe
to run on a daily driver.

```bash
adb push tools/phase0/observe.sh /data/local/tmp/
adb shell 'chmod 755 /data/local/tmp/observe.sh'
adb shell 'su -c "sh /data/local/tmp/observe.sh"' > result.txt
```

Every section names the blueprint section it exists to verify. Keep that
mapping current — a probe whose findings cannot be traced to a design claim is
just noise.

| Section | Verifies |
|---|---|
| 1 | §4 kernel config floor |
| 2 | D10 / §12 — BTF, without which the `SK_STORAGE` map cannot be created |
| 3 | §8.4 — `rp_filter` / `accept_local` / `ip_forward`, the veth return path |
| 4 | §3.3.1 — `ARPHRD` type, which decides the L2 vs L3 egress entry |
| 5–6 | §8.5.1 / §8.5.2 / §8.5.3 — clsact lifecycle and who already owns which TC preference |
| 7 | §8.3 — is the 1..9999 `ip rule` window free, is table 20260 empty |
| 8 | §3.1 — which fwmark bits are actually in use |
| 9 | §0.1 item 2 — is any cgroup `SOCK_ADDR` slot actually attached |
| 10 | attached vs merely loaded; vendor BPF inventory |
| 11 | §1.3 — DNS posture |
| 12 | D8 — `packages.list` shape |
| 13 | leftover state and name collisions |

### Redaction

Output is redacted by default. Host portions of addresses, MAC addresses and
NFLOG cookies are masked, because the analytical value is in whether an address
exists and what scope it has, never in its value.

`FLUX_PROBE_RAW=1` disables redaction. **Never commit unredacted output** — the
previous repository shipped a device serial number into git history and that
mistake is why this filter exists.

### Two traps this tool exists to avoid

Both were found the hard way while writing it, and both would silently produce
a wrong conclusion:

1. **Sample TC filters more than once.** A vendor can attach its egress program
   minutes after the link is already carrying traffic. On SM-S9180, `wlan0` had
   `clsact` and a global address but no filter; Samsung's program appeared
   several minutes later. A one-shot conflict check at activation time reports
   "preference 1 is free" and is wrong shortly afterwards.

2. **`loaded_at` is not the attach time.** `bpftool prog show` reports when the
   *program* was loaded, which on Android is a few seconds after boot for
   everything the bpfloader pins. Attachment happens later and separately. Do
   not infer occupancy from load time.

## Results

`results/` holds redacted, analysed snapshots. One file per device and build.
The analysis that matters is folded back into `docs/history/phase0.md` —
these files are the raw evidence behind it, kept so that a future claim can be
checked against what was actually measured rather than what was remembered.

Findings that changed the design are tracked separately in
`docs/history/review-log.md`, including the ten times the design was overturned
by its own evidence. Three of those came out of these harnesses, and two of the
three overturned claims the design itself had made.
