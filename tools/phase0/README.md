# Phase 0 tooling

Phase 0 is the falsification step that runs **before** implementation. Its
purpose is to break assumptions cheaply, on real hardware, while changing them
is still free. It splits in two:

| Half | What it does | Tool |
|---|---|---|
| **Observation** | Answers "what is this device actually like" | `observe.sh` (read-only) |
| **Falsification** | Answers "does the mechanism work here" — Q1–Q10 in `docs/blueprint.md` §16.1 | not written yet; needs a loadable BPF object |

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
The analysis that matters is folded back into `docs/blueprint.md` §16.2 — these
files are the raw evidence behind it, kept so that a future claim can be
checked against what was actually measured rather than what was remembered.
