//! Network object lifecycle, control leaf publication and interface admission.
//!
//! Implements blueprint §8. Three rules that are safety properties, not style:
//!
//! * **Ownership predicate before every mutation.** Flux touches an object only
//!   if it matches the full predicate (netns, ifindex, ifname, parent,
//!   direction, kind, direct-action, program name, map set, dump order). If an
//!   unknown object holds our identity we stay `Inactive` and report; we never
//!   overwrite or delete it.
//! * **Never delete the `clsact` qdisc.** Flux may create one when absent but
//!   removing it would break tethering and CLAT. Only our own filters are
//!   deleted, by exact `prio` / `protocol` / `handle` / `kind` (§8.5).
//! * **Never write a global sysctl.** If the effective `all.rp_filter` is
//!   non-zero we stay `Inactive` and report, rather than silently weakening a
//!   device-wide security setting (§8.4).
//!
//! Not implemented yet — Phase 4 (blueprint §17).
