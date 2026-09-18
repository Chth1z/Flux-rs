# Failure Matrix and `status` Specification

> Former Parts 23 and 24 of blueprint.md. **Section numbers are unchanged**: every §N.x here is the same §N.x cited throughout the repository (see AUTH-1.1).
>
> Audience: anyone looking up the meaning of an error code. The normative contract is `blueprint.md`, which is complete on its own.

---

# Part 23: Failure Matrix

Every possible failure point specifies **how it is detected, what action is taken, and what the user sees**. Rule: the "Action" column of every row MUST NOT contain an ambiguous phrase such as "log and continue" (§15.4(1) state honesty).

## 23.1 Startup: not yet active, Direct throughout

| Failure point | Detection | Action | User-visible result |
|---|---|---|---|
| Second instance | `flock(LOCK_EX\|LOCK_NB)` fails | Immediately `exit(3)` — the code the supervisor treats as "do not restart" (§13.2.2); **touch no object and do not unlink the socket** | Second invocation reports "already running" and names the holder's pid |
| page size ≠ 4096 | `sysconf(_SC_PAGESIZE)` | Remain `Inactive`; **do not start the engine or create any object** | `status.last_error = "unsupported_page_size:16384"` |
| netns is not the initial netns | Compare the inodes of `/proc/self/ns/net` and `/proc/1/ns/net` | `Inactive` | `"netns_mismatch"` |
| A symlink or a non-directory sits where the state root, `run/` or `config/` must be | `symlink_metadata` on each of the three, every start and every convergence | `Inactive`; **MUST NOT replace, unlink or follow it** — the object is not Flux's (PHIL-5) | `"runtime_dir_type:<path> expected directory"` |
| The state root's mode or owner has drifted from `root:root 0700` | the same inspection | **Not a failure.** The three directories are Flux's own (§11.1): restore `0700` and the owner, log one line per repair, continue. An earlier revision refused to run here, on the theory that the user may have loosened the mode deliberately; but `/data/adb` is itself root-only, so the mode protected nothing, and the boot script was tightening it anyway — the refusal contradicted the script and belonged in neither (PHIL-7) | `fluxd.log`: `state root repaired: <path>: mode 0755 restored to 0700` |
| `uname -r` has no GKI line Flux ships | `gki_line::from_uname_release` | `Inactive`; load nothing | `"lkm_unknown_release:<uname -r>"` (`fluxd check` is an error on Android and a warning on a development Linux host) |
| No `fluxrs-androidN-X.Y*.ko` in the kmod directory | directory list | `Inactive` | `"lkm_missing_module"` |
| `.ko` is not ELF64 or has no `vermagic=` | `.modinfo` parse | `Inactive` if `finit_module` is attempted; `fluxd check` fails closed | `"lkm_corrupt_module:<reason>"` |
| Module vermagic and `uname -r` map to different GKI lines | `modinfo::relate` | `fluxd check` fails; load is still `finit_module` | `"lkm_vermagic:<vermagic> kernel:<uname -r>"` |
| Module vermagic differs but the GKI line matches | `modinfo::relate` | **Warning only.** `finit_module` remains the gate (§0.6.32) | `"lkm_vermagic:<vermagic> kernel:<uname -r> (same GKI line; finit_module is the gate)"` |
| `finit_module` fails (not `EEXIST`) | errno | `Inactive`; **MUST NOT** create veth or attach TC. Detail includes vermagic and `uname -r` when they can be read | `"lkm_finit:<errno>"` |
| `/dev/fluxrs` will not open | errno (`EACCES` / `EBUSY` / …) | `Inactive`; drop any partial load | `"lkm_control"` |
| Reading or listing the `.ko` fails before the syscall | errno | `Inactive` | `"lkm_io"` |
| `nf_tproxy_*` unresolved (`steal_ready=0`) | `GET_STATUS` | drop the fd; `Inactive` | `"lkm_tproxy_symbol"` |
| `/dev/fluxrs` is not held when policy or listeners must be published | `kmod` fd absent | keep `active=0`; do not steal | `"lkm_not_loaded"` |
| Selected UID count exceeds `UID_SELECTED_MAX` (1024); the LOCAL_OUT `SET_UIDS` table is the same cap | count | Reject the hot update; retain the current policy | `"policy_capacity:selected"` |
| Selected UID count exceeds the former 64-slot ioctl table | count | **Superseded.** `UID_SLOT_MAX` is 1024, lockstep with the ABI. Old status lines may still carry this token. | `"policy_capacity:kmod_uids"` (historical) |
| `all.rp_filter != 0` | Read `/proc/sys/...` | **Superseded (C13).** LOCAL_OUT does not consult `rp_filter`. Startup MUST NOT fail closed on this value. The token remains so old status lines parse. | `"rp_filter_conflict:all=1"` (historical) |
| A veth with the same name exists but its alias does not match | `RTM_GETLINK` + `IFLA_IFALIAS` | **Superseded as a startup gate (C13).** Unique dataplane does not create `flxrs*`. Leftover owned pairs are deleted in §8.7 step 2; a name match without the predicate is still a conflict if cleanup sees it. | `"veth_conflict:flxrs0 alias mismatch"` |
| MTU 65535 is rejected | ACK from `RTM_NEWLINK` | **Superseded as a startup gate (C13).** Unique dataplane does not create veth. | `"veth_mtu_rejected"` |
| RPDB priority 100 is occupied | `RTM_GETRULE` dump | **Superseded as a startup gate (C13).** Unique dataplane does not install pref 100. Leftover owned rules are deleted in §8.7 step 2. | `"rule_conflict:priority 100 occupied"` |
| table 20260 contains an unknown route | `RTM_GETROUTE` dump where `rtm_protocol != 202` | **Superseded as a startup gate (C13).** Unique dataplane does not install table 20260. | `"route_table_conflict:20260"` |
| BTF load fails | errno from `BPF_BTF_LOAD` | `Inactive` | `"btf_load:EINVAL"` |
| SK_STORAGE map creation fails | errno from `BPF_MAP_CREATE` | `Inactive` | `"map_create:tcp_decision:EINVAL"` |
| Program verifier rejects a program | errno from `BPF_PROG_LOAD` | `Inactive`; **write the first N lines of the verifier log to both the log and status** (§12.7 item 11) | `"prog_load:flx_cap_l2:EACCES"` + log summary |
| SELinux denies BPF load/attach | `EPERM`/`EACCES` | `Inactive`; **do not inject sepolicy** (§1.3 non-goal) | `"bpf_denied:check root manager policy"` |
| `packages.list` is unreadable | errno from `open` | Retain the current policy; on cold start, `Inactive` | `"packages_list_unreadable"` (`fluxd check` appends `: <errno>`) |
| A configured package does not exist | Table lookup misses after parsing | Reject the entire candidate configuration; **do not apply it partially** | `"selector_invalid"` + detail identifying the entry |
| A configured package runs as root (`appId` 0) | Composition refuses it (§1.4) | Same as above — and no spelling of the entry can work, so the detail says why rather than suggesting a fix | `"selector_invalid"` + detail identifying the entry |
| A configured package is a platform uid outside `[10000, 19999]` | Same composition, which accepts it | **Warning only.** It is applied; `check` and `status` name the entry and what it costs (uid 1000 breaks Android's connectivity validation while the proxy is down) | warning naming the entry |
| Engine binary is missing (incomplete module installation / test environment) | `stat` the engine path | `Inactive`; do not enter the §9.4 transaction | `"engine_binary_missing:<path>"` |
| `config/template.json` is missing or unreadable | errno from `open` | Cold start: `Inactive`; hot update: retain the current generation | `"engine_config_missing"` / `"engine_config_unreadable:<errno>"` |
| The template fails to parse: non-UTF-8, or invalid JSONC syntax | `parse_jsonc` | Cold start: `Inactive`; hot update: retain the current generation | `"engine_config_invalid"` + specific reason in warnings |
| A template group is empty and there is no node to fill it with | `generate_from_template` (§28.2) | Cold start: `Inactive`, Direct — a template is not a configuration and the engine rejects an empty group outright; hot update: retain the current generation | `"engine_config_unfilled"` + the group tags and the two ways to fill them |
| Nodes are present but no group selects them | `unreferenced_node_tags` on the generated config | **Warning only.** The configuration is valid and the user may mean it; `status` and `check` state that selected apps still egress direct | `"nodes_unreferenced"` |
| The template fails validation: declares an inbound, uses a reserved tag, or is not an object | `build_effective` in `flux-core` | Same as above | `"flux_config_invalid"` + specific reason in warnings |
| Subscription fetch fails: DNS, TLS, HTTP status, timeout, batch deadline, or total body cap | the fetch itself | Keep the current generation; **retry when rtnetlink reports a usable default route**, never on a fixed interval (§29.4). 4xx and oversize are not retried. A late result whose fetch epoch no longer matches is discarded | `"subscription_fetch_failed:<reason>"` including `deadline_exceeded` |
| Subscription content yields zero non-infrastructure outbounds | count after refinement (§28.4) | Refuse the candidate, keep the current generation | `"subscription_empty"` — an error page can be valid JSON and can pass `check` while containing no node |
| `sing-box check` fails | Child exit code + stderr | Cold start: `Inactive`; hot update: retain the current generation | `"engine_check_failed"` + first several lines of stderr |
| Engine fails to start | pidfd becomes readable immediately | Retry with backoff (1/2/4/8/30 s) | `"engine_exited:code=1"` |
| The 4 sockets do not appear before the deadline | Timed-out SOCK_DIAG ProbeReady with backoff | Stop the candidate; `Inactive` | `"engine_not_ready:2/4 sockets"` |
| SOCK_DIAG dump is incomplete (`NLMSG_DONE` missing, `NLM_F_DUMP_INTR`, truncated) | Completeness gate; retry until the readiness deadline | Do **not** treat as absent; disable and stop remain serviceable between datagrams | still Waiting, then `"engine_not_ready"` if the deadline expires |
| Socket inode does not belong to the candidate pid | Cross-check `/proc/<pid>/fd` | Stop the candidate; `Inactive` | `"engine_socket_owner_mismatch"` |
| `clsact` has a shared block | Dump contains `TCA_INGRESS_BLOCK`/`EGRESS_BLOCK`, or non-empty `TCA_OPTIONS` | **Exclude that interface**; continue with the others | That interface is `excluded(clsact_shared_block)` |
| `clsact` dump carries an unknown or duplicated attribute | The allowlist parse of §8.5 fails | **Exclude that interface**; fail closed rather than adopt a qdisc Flux cannot fully read | That interface is `excluded(clsact_foreign)` |
| No usable pref (1–3 are all occupied on `v4-*`) | Dump + §8.5.3 | Exclude that interface | `excluded(tc_no_usable_pref)` |
| The acquired pref is shadowed by an earlier filter | §8.5.4 liveness verification: tx increases but `SAW_PACKET` does not | Exclude that interface and identify the shadowing filter | `excluded(tc_chain_shadowed)` |
| No traffic during the liveness verification window | tx does not increase either | Retry with backoff; if there is still no traffic at the limit, permit activation and annotate it | `warn(tc_verify_no_traffic)` |
| Flux filter reachability cannot be proven | Identity and relative-order checks plus positive `flx_verify` liveness verification | Exclude that interface. **MUST NOT exclude it merely because it is not the first dump entry** | tx increases while the probe does not: `excluded(tc_chain_shadowed)`; identity or preceding-snapshot drift: `excluded(identity_drift)` |
| More than 64 candidate interfaces | Count | **Do not promote the entire new topology**; retain the current topology/Direct, and do not truncate by name | `"too_many_interfaces:71"` |

## 23.2 Runtime: already active

| Failure point | Detection | Action | Data-plane consequence |
|---|---|---|---|
| Engine process exits | pidfd is readable | publish `active=0` → restart with backoff → new generation | New flows are Direct (listener lookup miss); admitted TCP is dropped |
| One engine listener closes while the process remains alive | `EGRESS_LISTENER` in BPF `fault_events` | publish `active=0` → restart the entire generation | Same as above. **This is the sole reason the fault ringbuf exists** |
| Engine event-loop livelock (listener and process both remain present) | **Undetectable** (§2.2.3(3)) | None | New flows continue to be captured and stall during this period. **Published residual risk** |
| ingress `bpf_sk_assign` repeatedly fails | `counters[IN_DROP_ASSIGN] > 0` and `admit_* > 0` | `status` gives a **specific hypothesis**: "engine listener may have SO_REUSEPORT — kernels < 6.5 reject assign (§9.2)" | Admitted flows are dropped |
| **netd deletes `clsact` from a physical interface** (which also deletes our egress filter) | `RTM_DELQDISC` / `RTM_DELTFILTER` | Exclude it as `netd_clsact_missing` and wait for netd to recreate it; after `RTM_NEWQDISC`, run admission again. Flux never creates physical `clsact`. While other active coverage remains, leave global `active` unchanged; if this was the last one, publish inactive per R091-10 | Capture-side drift; selected traffic on this interface is Direct during the window |
| An owned **core** object (`flxrs0/1`, ingress filter, rule, local route) is deleted externally | rtnetlink event + on-demand dump | First publish `active=0`, then reconverge under the §8.5 predicates | New flows are Direct during convergence |
| An unknown object occupies our identity | Dump comparison fails | Remain `Inactive` and report it; **do not overwrite or delete the object** | Direct |
| Interface disappears | `RTM_DELLINK` | The kernel has also deleted its filter; remove it from the active set. If this was the last active capture interface, first publish `active=0` and enter `Inactive`; otherwise remain `Active` | Flows on that interface return to the Android path (R091-10) |
| Interface appears | `RTM_NEWLINK` + admission | Attach after debounce; if zero coverage previously caused `Inactive`, publish `active=1` again after the admission + readiness loop closes | Direct during the window (R091-10) |
| Netlink socket overflows | `ENOBUFS` / `NLMSG_OVERRUN` | **Discard the batch and perform a complete new dump** (§10.4.1 item 2) | None (control-plane internal) |
| Map update fails during a policy hot update | errno from `bpf_map_update_elem` | Keep the live epoch unchanged; record the error and **enqueue one complete convergence again**; do not unwind by mutating the live bank (§10.5) | New flows keep seeing the **complete old epoch**. A mixed epoch is a defect, not a benign window |
| `publish_inactive` has no reserved control leaf | spare FD absent after freeze (or syscall failure on the swap) | `inactive_publish_failed`; do not report capturing; stop the engine; **do not `MAP_CREATE` on this path** | New flows should fail open once `active=0` is visible; if the swap itself failed, admitted TCP may still drop until a later successful inactive publish |
| The `disable` file metadata is neither success nor `NotFound` | `EIO` / `EACCES` / … | Treat as **Unreadable**: do not enable capture; `status` reports the path could not be observed (§11.1, §27.1.1) | Capture stays off. Not the same as "file absent" |
| `uid_policy` exceeds 4096 or more than 1024 entries are simultaneously `SELECTED` | Count each separately | Reject the hot update and retain the current policy | No change |
| Any bypass LPM exceeds 65536 | Count by address family; local addresses do not count toward the LPM | **Reject activation and report it**; do not silently discard entries | Direct |
| Any self-address HASH exceeds 256 | Count exact addresses by address family | **Reject activation and report it**; do not silently discard entries | Direct |
| Control socket receives a non-root request | `SO_PEERCRED.uid != 0` | Close the connection | Client EOF |
| Control request exceeds 64 KiB | Read length | Close the connection | Same as above |
| Decision storage allocation fails | Both calls to `bpf_sk_storage_get` return NULL | Current packet gets `TC_ACT_UNSPEC` (no stickiness) | This SYN goes Direct; later SYNs may be evaluated again (§2.2.1 final item) |
| `flux_decision.magic` or `reserved` is corrupt | Validate on every read | `TC_ACT_SHOT` + `counters[DROP_CORRUPT]` | All later packets on this socket are dropped (no leak) |
| Control snapshot ABI magic does not match | Validate on every `ctrl()` call | egress: admitted SHOT / unadmitted UNSPEC; ingress: SHOT | See §2.2 |
| On a kernel < 6.5, assign targets a listener that has just been unhashed | **Undetectable** | None | One socket reference leaks. The §9.4 ordering narrows the window to the hundreds of microseconds between "engine crash → pidfd wakeup." **Known and accepted** (§9.2) |

## 23.3 Stop and crash

| Scenario | Behavior | Residue |
|---|---|---|
| `fluxd stop` | publish `active=0` → `SIGTERM` engine → short deadline → `SIGKILL` → confirm via pidfd → exit normally (0) | veth/BPF/TC objects **remain** (deleted and recreated on the next start); service.sh does not restart after exit code 0 |
| Disable the module in the manager | The manager creates `/data/adb/modules/Flux-rs/disable`; inotify wakes the daemon, which then behaves as in the next row | Same as the next row; no reboot required |
| `fluxd disable` | Create the same `disable`, publish `active=0`, and stop the engine; the daemon continues running and waiting for commands | Same as above; "disabled" does not mean network objects have been removed during the same boot |
| `SIGTERM` / `SIGINT` | Same as `stop` | Same as above |
| The reactor receives `SIGKILL` | The kernel terminates the engine because of `PDEATHSIG=SIGKILL` → listener disappears → **new flows are Direct because listener lookup misses**; admitted TCP packets are dropped at ingress after redirect | TC filters + veth + rule + route all remain. **This is the critical fail-open path**: the remaining capture program cannot form a black hole because it first looks up the listener on every invocation |
| The supervisor restarts the reactor (§13.2.2), after the 1/2/4/8/30 s backoff | §8.7 step 2 deletes every precisely owned residual object before rebuilding | None |
| The supervisor itself is killed | Nothing changes for traffic: the reactor keeps running and keeps the lock, only unsupervised. A later `fluxd daemon` is rejected as a second instance | None |
| Device reboots | All non-persistent kernel objects disappear naturally | None |
| Module is uninstalled | `uninstall.sh` synchronously requests `fluxd stop`, then deletes only `/data/adb/flux-rs` | Kernel objects remain until reboot; **MUST NOT flush any system object** |

**Invariant across the entire table**: `Inactive` proves only that `control.active=0` and new flows are no longer admitted; it does not prove that TC/veth/rule/route/map objects have been deleted. Before `status` reports "cleaned" or "no residue," it MUST have a **fresh actual enumeration** (TC dump, `RTM_GETRULE`, `RTM_GETROUTE`, `BPF_OBJ_GET_INFO_BY_FD`) proving that the objects are absent. If that cannot be proven, it MUST NOT make a cleanup claim and MUST include the first concrete error.

---

# Part 24: `status` Output and Error Code Specification

`status` is this product's only diagnostic surface (there is no WebUI, periodic logging, or telemetry). It MUST be sufficient to answer "why did it not take effect"; otherwise the "zero observability" defect from §14.2 returns.

## 24.1 Field specification

```jsonc
{
  "ok": true,
  "version": "0.9.0",                // Sole source is the workspace manifest; bump with each release
  "abi_magic": "0xF10C0905",          // Whatever bpf/include/flux_abi.h defines; an example, not a pin
  "state": "Disabled" | "Inactive" | "Active",
  "root_manager": "KernelSU",         // Detected manager; null when unknown
  "generation": 7,
  "backoff_seconds": null,            // Remaining seconds while the engine is backing off before a retry
  "engine": {
    "running": true, "pid": 1234,
    "sockets_verified": 4,            // Expect 4; fewer than 4 means readiness has not closed
    "effective_config": "run/sing-box.7.json"
  },
  "policy": {
    "selected": 3, "draining": 1,
    "bypass_v4": 12, "bypass_v6": 6,  // RESERVED + POLICY prefixes; local addresses are separate
    "self_addresses": 4               // Total dynamic local addresses in the two exact HASH maps
  },
  "ssid": {                            // The [ssid] dimension of §29; null when its list is empty
    "connected": true,                 // A station interface has a BSS; null when nl80211 could not be read
    "paused": false,                   // The dimension is holding Flux Inactive (§29.5)
    "matched_entry": null              // 1-based position in the expanded list of the entry that caused a pause
  },                                   // The SSID itself never appears here (§29.5)
  "ifaces": [
    { "name": "wlan0", "ifindex": 24, "arphrd": "ether",
      "entry": "flx_cap_l2", "status": "active",
      "prog_id": 118, "prog_tag": "a1b2c3d4e5f60718",
      "pref": 2,                       // Preference actually occupied on this interface; selected per interface
      "reachable": true },             // Verified by flx_verify; never means first in the dump
    { "name": "rmnet_data0", "ifindex": 30, "arphrd": "rawip",
      "entry": "flx_cap_l3", "status": "admitted",
      "pref": 2, "…": null },          // reachable absent: liveness verification is not yet conclusive
    { "name": "v4-rmnet_data0", "ifindex": 31, "arphrd": "none",
      "status": "excluded", "reason": "clat_order_unverified" }
  ],
  "counters": {                        // Sum of the PERCPU_ARRAY from §6.1
    "admit_tcp": 41, "direct_tcp": 190, "admit_udp": 388,
    "drop_inactive": 0, "drop_stale_gen": 0, "drop_handoff": 0,
    "drop_selected_fragment": 0, "drop_corrupt": 0, "decision_alloc_fail": 0,
    "egress_listener_miss": 2,
    "in_assign_tcp": 41, "in_assign_udp": 388,
    "in_pass_established": 5120, "in_pass_fragment": 0,
    "in_drop_no_listener": 0, "in_drop_assign": 0,
    "in_drop_parse": 0, "in_drop_snapshot": 0
  },
  "sysctl": { "all.rp_filter": 0, "flxrs1.rp_filter": 0, "flxrs1.accept_local": 1 },
  "warnings": [ /* See 24.3 */ ],
  "hints":    [ /* See 24.4 */ ],
  "last_error": null
}
```

The presence of `/data/adb/modules/Flux-rs/disable` means the desired state is disabled—that is the manager's own module switch, and `fluxd` watches it with inotify. While the engine is still terminating or convergence remains busy, the top-level state MAY briefly be `Inactive` with a pending warning; it becomes `Disabled` only after completion. None of these three states alone promises cleanup.

`fluxd` also renders the same state as one line in `module.prop` under `description=` for display in the manager's module list; that is only a **projection**, and the JSON here remains authoritative.

## 24.2 Error code naming rules

`last_error` and `ifaces[].reason` MUST always use **stable identifiers** in `snake_case`, optionally followed by `:` and a concrete value. These two fields **MUST NOT** contain free text (free text belongs in `warnings`). The defined set is exactly the values present in the two §23 tables; any addition MUST update §23 at the same time.

Four prefix classes support routing:

| Prefix | Meaning | Example |
|---|---|---|
| `unsupported_*` | Device capability is insufficient; retrying is useless | `unsupported_page_size:16384` |
| `*_conflict` | Another owner's object occupies the slot; manual intervention is required | `rule_conflict:priority 100 occupied` |
| `*_failed` / `<syscall>:<errno>` | Operation failed and may be retryable | `prog_load:flx_cap_l2:EACCES` |
| `excluded(<reason>)` | One interface is excluded while the others continue working | `excluded(tc_chain_shadowed)` |

`identity_drift` means the attachment identity, or a previously verified snapshot of the filters ahead of ours, no longer holds. It replaces the token `not_first_applicable`, whose name asserted something dump position never established. Human-facing text says "unreachable" or "reverification required", and **MUST NOT claim Flux has to be the first dump entry**.

`ifaces[].reachable` is tri-state, and omission carries meaning: an absent field means no conclusion has been reached — `flx_verify` has no result yet, or the interface was never observed because of a condition such as `tc_dump_failed`; `true` means reachability was verified; `false` means it was definitively found unreachable through shadowing, identity drift or attach failure. **Absence MUST NOT be read as `false`**, because that would report "the user was not online during the window" as "a vendor filter is shadowing us" — the benign case and the failure the check exists to find.

## 24.3 Warnings that MUST be produced

| Condition | Warning |
|---|---|
| A selected package declares `BIND_VPN_SERVICE` (best-effort detection) | `"0:com.foo declares BIND_VPN_SERVICE; its outer socket will be captured"` |
| A selected UID has other shared-UID sibling packages | `"uid 10231 also covers: com.bar, com.baz"` |
| User JSON lacks :53 handling | `"no hijack-dns rule; selected apps' DNS will be forwarded verbatim and domain rules will not apply"` (§1.3.4) |
| System Private DNS is not `off` | `"system private DNS is on; name resolution bypasses Flux"` (§1.3.3 boundary ①) |
| Captured :53 traffic has `sk_uid == 1051` | `"enforce_dns_uid appears enabled; system DNS is not per-app attributable on this device"` (boundary ②) |
| The user set outbound `routing_mark` / `bind_interface` | `"user-set outbound routing_mark/bind_interface: Android network consequences are yours"` |
| Flux did not create `clsact` | `"clsact on wlan0 pre-existed; it will never be deleted by Flux"` |
| A complete TCP `SOCK_DIAG` dump could not be assembled while unselecting | `"sock_destroy_incomplete: live TCP of unselected UIDs was not reset"` |
| `SOCK_DESTROY` itself failed after a complete dump | `"sock_destroy_failed:<error>"` |
| Module vermagic and `uname -r` share a GKI line but are not identical | `"lkm_vermagic:<vermagic> kernel:<uname -r> (same GKI line; finit_module is the gate)"` |
| `[ssid]` has entries but `nl80211` is unavailable or the interface dump failed | `"ssid_unreadable: Wi-Fi state cannot be read; the [ssid] list is not applied"` (§29.5 — activation is not blocked) |
| The `[ssid]` dimension is holding Flux inactive | `"ssid_paused: the connected Wi-Fi network is excluded by [ssid]; Flux resumes when it changes"` |

## 24.4 Hints that MUST be produced: turning counter combinations into hypotheses

The opposite of zero observability is not "print more numbers"; it is to **perform the first layer of reasoning for the user**:

| Counter combination | Hint |
|---|---|
| `admit_* > 0` and `in_drop_assign > 0` | `"assign is failing; if this is 100% the engine listener may have SO_REUSEPORT (kernels < 6.5 reject it)"` |
| `admit_* > 0` and `in_drop_no_listener > 0` | `"packets reached LOCAL_OUT but no listener was found; engine may be restarting"` |
| `egress_listener_miss > 0` and `admit_* == 0` | `"nothing is being captured because the engine listener is absent"` |
| `direct_tcp > 0` and `admit_tcp == 0` | `"selected UIDs are matching but every first SYN chose DIRECT; check the [cidr] mode and list, and active"` |
| All counters are 0 and `state == Active` | `"no selected traffic observed; verify the app list resolves to the UIDs you expect"` |
| `drop_selected_fragment > 0` | `"selected-app IP fragments with no TCP decision are dropped by design (§7.3); large DNS/QUIC payloads may fail"` |
| `in_pass_established` is much greater than `in_assign_tcp` | Normal (one assign and many passes per connection). **Produce no hint**; this row exists only to prevent a false positive |

---
