//! Pure §26 lifecycle: phases, stimuli, effects, and the status projection.
//!
//! The daemon's epoll loop is an adapter over [`step`]. Illegal combinations of
//! disable / engine / dataplane flags are not representable as a [`Phase`].
//! The JSON `State` and the `module.prop` line are both projections of one
//! [`CommittedView`] (blueprint §10.1, §26, §27.1.3).

use crate::control_wire::State;

/// Internal lifecycle phase. Distinct from the three-value wire [`State`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The manager switch is off and no engine work remains.
    Disabled,
    /// Disable or shutdown has been requested; the engine has not yet exited.
    Stopping,
    /// Enabled, but `[ssid]` holds capture inactive (§29.5).
    Paused,
    /// Enabled, no committed generation, no in-flight activation.
    Inactive,
    /// An engine candidate or Phase 6 attach is in flight.
    Activating,
    /// Control `active=1` is committed and at least one capture interface is live.
    Active,
}

/// A §26 table event, plus the completions the table implies but does not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stimulus {
    /// Process start finished constructing the reactor.
    Bootstrap,
    /// The disable file disappeared.
    Enable,
    /// The disable file appeared.
    Disable,
    /// Control `reload` or equivalent.
    Reload,
    /// Control `stop`.
    Stop,
    /// Control `status`. Read-only.
    Status,
    /// Control `check`. Read-only.
    Check,
    /// A physical interface appeared.
    NewInterface,
    /// A physical interface disappeared.
    InterfaceGone {
        /// True when the departing interface was the last active capture iface.
        last_active_iface: bool,
    },
    /// An address on an admitted interface changed.
    AddressChange,
    /// Physical `clsact` or our egress filter was deleted (§26 invariant 4).
    CaptureSideDrift,
    /// `flxrs0`/`flxrs1`, ingress filter, rule or local route drifted.
    CoreDrift,
    /// rtnetlink `ENOBUFS` or overrun.
    NetlinkOverrun,
    /// `flux.toml` changed.
    FluxTomlChanged,
    /// `template.json` or a `@file` list changed.
    TemplateOrListChanged,
    /// `packages.list` changed.
    PackagesChanged,
    /// `[ssid]` now pauses.
    SsidPause,
    /// `[ssid]` no longer pauses.
    SsidResume,
    /// pidfd: the engine child exited.
    EngineExited,
    /// Ringbuf event for the committed generation.
    CurrentGenerationFault,
    /// Ringbuf event for an old generation, or a duplicate.
    StaleOrDuplicateFault,
    /// Trailing debounce timer.
    DebounceExpired,
    /// Crash/retry backoff timer.
    BackoffExpired,
    /// Candidate SOCK_DIAG backoff timer.
    ReadinessBackoff,
    /// `SIGHUP`.
    Sighup,
    /// `SIGTERM` / `SIGINT`.
    Sigterm,
    /// Phase 6 published `active=1`.
    ActivationCommitted,
    /// Phase 6 or candidate start failed before commit.
    ActivationFailed,
    /// The engine child has been reaped while stopping.
    EngineStopped,
}

/// A userspace action [`step`] asks the adapter to perform. No syscalls here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Combination absent from §26: log and ignore; do not invent handling.
    IgnoreUnexpected,
    /// Run the full activation sequence (§8.7).
    AttemptActivation,
    /// Terminate the engine generation (pidfd-driven).
    StopEngine,
    /// Publish `active=0` before any other leave-Active work (§26 invariant 1).
    PublishInactive,
    /// Process exit 0 after capture is frozen.
    ExitProcess,
    /// Re-validate configuration; change nothing in the data plane.
    RevalidateOnly,
    /// Commit one PolicyEpoch; leave `active` untouched (§10.5).
    PolicyTransaction,
    /// Engine candidate switch (§9.4).
    EngineCandidateSwitch,
    /// Re-evaluate interface admission.
    ReevaluateAdmission,
    /// Admit and attach one new interface; failure excludes only that iface.
    AdmitAndAttach,
    /// Drop one interface from the active set.
    ExcludeInterface,
    /// Update self-address maps additively; leave `active` untouched.
    UpdateSelfAddresses,
    /// Re-attach one egress filter. MUST NOT freeze capture (§26 invariant 4).
    ReattachCaptureLocally,
    /// Full topology re-dump.
    FullRedump,
    /// Regenerate the engine config, then a candidate switch.
    RegenerateThenSwitch,
    /// Re-parse packages, then a policy transaction.
    ReparseThenPolicy,
    /// Restart the engine with the crash backoff.
    RestartWithBackoff,
    /// Clear the fault latch; do not restart.
    ClearLatchOnly,
    /// Consume the pending event set in one convergence.
    RunPendingConvergence,
    /// Retry activation / engine start.
    RetryActivation,
    /// Re-check SOCK_DIAG for the candidate.
    RecheckSockDiag,
}

/// Result of one [`step`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Phase after the stimulus.
    pub phase: Phase,
    /// Adapter actions, in order. Empty means "no userspace work".
    pub effects: Vec<Effect>,
}

fn stay(phase: Phase) -> Step {
    Step {
        phase,
        effects: Vec::new(),
    }
}

fn with(phase: Phase, effects: &[Effect]) -> Step {
    Step {
        phase,
        effects: effects.to_vec(),
    }
}

fn unexpected(phase: Phase) -> Step {
    with(phase, &[Effect::IgnoreUnexpected])
}

/// Advance the lifecycle. Combinations absent from §26 yield
/// [`Effect::IgnoreUnexpected`] and leave the phase unchanged.
pub fn step(phase: Phase, stimulus: Stimulus) -> Step {
    match (phase, stimulus) {
        (_, Stimulus::Status | Stimulus::Check) => stay(phase),

        (Phase::Disabled | Phase::Stopping, Stimulus::Bootstrap) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::Bootstrap) => {
            with(phase, &[Effect::AttemptActivation])
        }
        (Phase::Activating | Phase::Active, Stimulus::Bootstrap) => unexpected(phase),

        (Phase::Disabled, Stimulus::Enable) => with(Phase::Inactive, &[Effect::AttemptActivation]),
        (
            Phase::Stopping | Phase::Inactive | Phase::Paused | Phase::Activating | Phase::Active,
            Stimulus::Enable,
        ) => stay(phase),

        (Phase::Disabled | Phase::Stopping, Stimulus::Disable) => stay(phase),
        (Phase::Inactive | Phase::Paused | Phase::Activating, Stimulus::Disable) => {
            with(Phase::Stopping, &[Effect::StopEngine])
        }
        (Phase::Active, Stimulus::Disable) => with(
            Phase::Stopping,
            &[Effect::PublishInactive, Effect::StopEngine],
        ),

        (Phase::Disabled | Phase::Stopping, Stimulus::Reload | Stimulus::Sighup) => {
            with(phase, &[Effect::RevalidateOnly])
        }
        (Phase::Inactive | Phase::Paused, Stimulus::Reload | Stimulus::Sighup) => {
            with(phase, &[Effect::AttemptActivation])
        }
        (Phase::Activating, Stimulus::Reload | Stimulus::Sighup) => stay(phase),
        (Phase::Active, Stimulus::Reload | Stimulus::Sighup) => with(
            Phase::Active,
            &[Effect::PolicyTransaction, Effect::EngineCandidateSwitch],
        ),

        (Phase::Disabled | Phase::Stopping, Stimulus::Stop | Stimulus::Sigterm) => {
            with(phase, &[Effect::ExitProcess])
        }
        (
            Phase::Inactive | Phase::Paused | Phase::Activating | Phase::Active,
            Stimulus::Stop | Stimulus::Sigterm,
        ) => with(
            Phase::Stopping,
            &[
                Effect::PublishInactive,
                Effect::StopEngine,
                Effect::ExitProcess,
            ],
        ),

        (Phase::Disabled | Phase::Stopping, Stimulus::NewInterface) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::NewInterface) => {
            with(phase, &[Effect::ReevaluateAdmission])
        }
        (Phase::Activating, Stimulus::NewInterface) => stay(phase),
        (Phase::Active, Stimulus::NewInterface) => with(Phase::Active, &[Effect::AdmitAndAttach]),

        (Phase::Disabled | Phase::Stopping, Stimulus::InterfaceGone { .. }) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::InterfaceGone { .. }) => {
            with(phase, &[Effect::ReevaluateAdmission])
        }
        (Phase::Activating, Stimulus::InterfaceGone { .. }) => stay(phase),
        (
            Phase::Active,
            Stimulus::InterfaceGone {
                last_active_iface: true,
            },
        ) => with(
            Phase::Inactive,
            &[Effect::PublishInactive, Effect::ExcludeInterface],
        ),
        (
            Phase::Active,
            Stimulus::InterfaceGone {
                last_active_iface: false,
            },
        ) => with(Phase::Active, &[Effect::ExcludeInterface]),

        (Phase::Disabled | Phase::Stopping, Stimulus::AddressChange) => stay(phase),
        (Phase::Inactive | Phase::Paused | Phase::Activating, Stimulus::AddressChange) => {
            with(phase, &[Effect::UpdateSelfAddresses])
        }
        (Phase::Active, Stimulus::AddressChange) => {
            with(Phase::Active, &[Effect::UpdateSelfAddresses])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::CaptureSideDrift) => stay(phase),
        (Phase::Inactive | Phase::Paused | Phase::Activating, Stimulus::CaptureSideDrift) => {
            with(phase, &[Effect::RunPendingConvergence])
        }
        (Phase::Active, Stimulus::CaptureSideDrift) => {
            with(Phase::Active, &[Effect::ReattachCaptureLocally])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::CoreDrift) => stay(phase),
        (Phase::Inactive | Phase::Paused | Phase::Activating, Stimulus::CoreDrift) => {
            with(phase, &[Effect::RunPendingConvergence])
        }
        (Phase::Active, Stimulus::CoreDrift) => with(
            Phase::Activating,
            &[Effect::PublishInactive, Effect::RunPendingConvergence],
        ),

        (Phase::Disabled | Phase::Stopping, Stimulus::NetlinkOverrun) => stay(phase),
        (_, Stimulus::NetlinkOverrun) => with(phase, &[Effect::FullRedump]),

        (Phase::Disabled | Phase::Stopping, Stimulus::FluxTomlChanged) => {
            with(phase, &[Effect::RevalidateOnly])
        }
        (Phase::Inactive | Phase::Paused, Stimulus::FluxTomlChanged) => {
            with(phase, &[Effect::AttemptActivation])
        }
        (Phase::Activating, Stimulus::FluxTomlChanged) => stay(phase),
        (Phase::Active, Stimulus::FluxTomlChanged) => {
            with(Phase::Active, &[Effect::PolicyTransaction])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::TemplateOrListChanged) => {
            with(phase, &[Effect::RevalidateOnly])
        }
        (Phase::Inactive | Phase::Paused, Stimulus::TemplateOrListChanged) => {
            with(phase, &[Effect::AttemptActivation])
        }
        (Phase::Activating, Stimulus::TemplateOrListChanged) => stay(phase),
        (Phase::Active, Stimulus::TemplateOrListChanged) => {
            with(Phase::Active, &[Effect::RegenerateThenSwitch])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::PackagesChanged) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::PackagesChanged) => {
            with(phase, &[Effect::ReparseThenPolicy])
        }
        (Phase::Activating, Stimulus::PackagesChanged) => stay(phase),
        (Phase::Active, Stimulus::PackagesChanged) => {
            with(Phase::Active, &[Effect::ReparseThenPolicy])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::SsidPause) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::SsidPause) => stay(Phase::Paused),
        (Phase::Activating | Phase::Active, Stimulus::SsidPause) => with(
            Phase::Paused,
            &[Effect::PublishInactive, Effect::StopEngine],
        ),

        (Phase::Paused, Stimulus::SsidResume) => {
            with(Phase::Inactive, &[Effect::AttemptActivation])
        }
        (_, Stimulus::SsidResume) => stay(phase),

        (Phase::Disabled, Stimulus::EngineExited) => unexpected(phase),
        (Phase::Stopping, Stimulus::EngineExited) => stay(Phase::Disabled),
        (Phase::Inactive | Phase::Paused, Stimulus::EngineExited) => {
            with(phase, &[Effect::RestartWithBackoff])
        }
        (Phase::Activating | Phase::Active, Stimulus::EngineExited) => with(
            Phase::Inactive,
            &[Effect::PublishInactive, Effect::RestartWithBackoff],
        ),

        (Phase::Disabled, Stimulus::CurrentGenerationFault) => unexpected(phase),
        (Phase::Stopping | Phase::Inactive | Phase::Paused, Stimulus::CurrentGenerationFault) => {
            with(phase, &[Effect::ClearLatchOnly])
        }
        (Phase::Activating | Phase::Active, Stimulus::CurrentGenerationFault) => with(
            Phase::Inactive,
            &[Effect::PublishInactive, Effect::RestartWithBackoff],
        ),

        (_, Stimulus::StaleOrDuplicateFault) => with(phase, &[Effect::ClearLatchOnly]),

        (Phase::Disabled | Phase::Stopping, Stimulus::DebounceExpired) => stay(phase),
        (_, Stimulus::DebounceExpired) => with(phase, &[Effect::RunPendingConvergence]),

        (Phase::Disabled | Phase::Stopping, Stimulus::BackoffExpired) => stay(phase),
        (_, Stimulus::BackoffExpired) => with(phase, &[Effect::RetryActivation]),

        (Phase::Disabled | Phase::Stopping, Stimulus::ReadinessBackoff) => stay(phase),
        (_, Stimulus::ReadinessBackoff) => with(phase, &[Effect::RecheckSockDiag]),

        (Phase::Activating, Stimulus::ActivationCommitted) => stay(Phase::Active),
        (Phase::Activating, Stimulus::ActivationFailed) => {
            with(Phase::Inactive, &[Effect::PublishInactive])
        }
        (_, Stimulus::ActivationCommitted | Stimulus::ActivationFailed) => unexpected(phase),

        (Phase::Stopping, Stimulus::EngineStopped) => stay(Phase::Disabled),
        (_, Stimulus::EngineStopped) => unexpected(phase),
    }
}

/// True when `effects` would freeze capture. Capture-side drift MUST NOT.
pub fn freezes_capture(effects: &[Effect]) -> bool {
    effects.contains(&Effect::PublishInactive)
}

/// Observable facts used only to reconstruct [`Phase`] after I/O completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// Manager `disable` file is present **or unreadable**. Unreadable is
    /// not enabled: capture must not start from this observation.
    pub disable_present: bool,
    /// SIGTERM/stop has been accepted.
    pub shutdown: bool,
    /// `[ssid]` is holding capture down.
    pub ssid_paused: bool,
    /// A supervised engine child exists.
    pub engine_present: bool,
    /// BPF control leaf `active==1`.
    pub dataplane_active: bool,
    /// Socket-ready child waiting for the Phase 6 commit.
    pub awaiting_commit: bool,
    /// An engine transaction or TC verification is in flight.
    pub convergence_busy: bool,
}

impl Phase {
    /// Rebuild the phase from committed runtime facts. Used after I/O, not as
    /// a second writer of policy: [`step`] remains the event table.
    pub fn observe(o: Observation) -> Self {
        if o.disable_present || o.shutdown {
            if o.engine_present || o.convergence_busy {
                return Phase::Stopping;
            }
            return Phase::Disabled;
        }
        if o.ssid_paused {
            return Phase::Paused;
        }
        if o.dataplane_active && o.engine_present && !o.awaiting_commit {
            return Phase::Active;
        }
        if o.engine_present || o.awaiting_commit || o.convergence_busy {
            return Phase::Activating;
        }
        Phase::Inactive
    }
}

/// Manager-list glyph. Strings stay in the daemon so this crate stays English.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayKind {
    /// §27.1.3 Active / RUNNING.
    Running,
    /// Enabled, concrete error.
    Failed,
    /// Enabled, converging, no error token.
    Starting,
    /// `[ssid]` pause.
    Paused,
    /// Disable complete.
    Stopped,
    /// Disable requested, engine still leaving.
    Stopping,
}

/// Shared projection for the JSON `state` and the `module.prop` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedView {
    /// Wire state (§10.1 / §24.1).
    pub state: State,
    /// Which §27.1.3 template to render.
    pub display: DisplayKind,
    /// Whether `engine.running` is reported. Only a committed generation.
    pub engine_running: bool,
}

/// Project [`Phase`] plus an optional stable error token.
pub fn project(phase: Phase, error: Option<&str>) -> CommittedView {
    match phase {
        Phase::Active => CommittedView {
            state: State::Active,
            display: DisplayKind::Running,
            engine_running: true,
        },
        Phase::Disabled => CommittedView {
            state: State::Disabled,
            display: DisplayKind::Stopped,
            engine_running: false,
        },
        Phase::Stopping => CommittedView {
            state: State::Inactive,
            display: DisplayKind::Stopping,
            engine_running: false,
        },
        Phase::Paused => CommittedView {
            state: State::Inactive,
            display: DisplayKind::Paused,
            engine_running: false,
        },
        Phase::Activating | Phase::Inactive => CommittedView {
            state: State::Inactive,
            display: if error.is_some() {
                DisplayKind::Failed
            } else {
                DisplayKind::Starting
            },
            engine_running: false,
        },
    }
}

/// Monotonic engine generation owner. `committed == 0` before the first
/// successful Phase 6 pointer swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generations {
    next: u64,
    committed: u64,
}

impl Default for Generations {
    fn default() -> Self {
        Self::new()
    }
}

impl Generations {
    /// First candidate is generation 1.
    pub fn new() -> Self {
        Self {
            next: 1,
            committed: 0,
        }
    }

    /// Allocate the next candidate id. Overflow is a programming error: a
    /// device will not live long enough to exhaust `u64`.
    pub fn allocate(&mut self) -> u64 {
        let id = self.next;
        self.next = self
            .next
            .checked_add(1)
            .expect("engine generation counter overflow");
        id
    }

    /// Record a successful Phase 6 commit.
    pub fn commit(&mut self, id: u64) {
        self.committed = id;
    }

    /// The last committed generation, or 0.
    pub fn committed(self) -> u64 {
        self.committed
    }

    /// The next id that [`Self::allocate`] will return.
    pub fn peek_next(self) -> u64 {
        self.next
    }

    /// A ringbuf fault is current only when it names the committed generation
    /// and the live child still carries that same id.
    pub fn fault_is_current(self, event_generation: u64, child_generation: Option<u64>) -> bool {
        self.committed != 0
            && event_generation == self.committed
            && child_generation == Some(self.committed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effects_of(phase: Phase, stimulus: Stimulus) -> Vec<Effect> {
        step(phase, stimulus).effects
    }

    fn phase_of(phase: Phase, stimulus: Stimulus) -> Phase {
        step(phase, stimulus).phase
    }

    #[test]
    fn status_and_check_never_mutate() {
        for phase in [
            Phase::Disabled,
            Phase::Stopping,
            Phase::Paused,
            Phase::Inactive,
            Phase::Activating,
            Phase::Active,
        ] {
            assert_eq!(step(phase, Stimulus::Status), stay(phase));
            assert_eq!(step(phase, Stimulus::Check), stay(phase));
        }
    }

    #[test]
    fn bootstrap_table() {
        assert_eq!(
            phase_of(Phase::Disabled, Stimulus::Bootstrap),
            Phase::Disabled
        );
        assert_eq!(
            effects_of(Phase::Inactive, Stimulus::Bootstrap),
            vec![Effect::AttemptActivation]
        );
        assert_eq!(
            effects_of(Phase::Active, Stimulus::Bootstrap),
            vec![Effect::IgnoreUnexpected]
        );
    }

    #[test]
    fn enable_disable_stop() {
        assert_eq!(
            step(Phase::Disabled, Stimulus::Enable),
            with(Phase::Inactive, &[Effect::AttemptActivation])
        );
        assert!(effects_of(Phase::Inactive, Stimulus::Enable).is_empty());
        assert!(effects_of(Phase::Active, Stimulus::Enable).is_empty());
        assert!(effects_of(Phase::Disabled, Stimulus::Disable).is_empty());
        assert_eq!(
            step(Phase::Inactive, Stimulus::Disable),
            with(Phase::Stopping, &[Effect::StopEngine])
        );
        assert_eq!(
            step(Phase::Active, Stimulus::Disable),
            with(
                Phase::Stopping,
                &[Effect::PublishInactive, Effect::StopEngine]
            )
        );
        assert_eq!(
            effects_of(Phase::Disabled, Stimulus::Stop),
            vec![Effect::ExitProcess]
        );
        assert!(effects_of(Phase::Active, Stimulus::Stop).contains(&Effect::PublishInactive));
        assert_eq!(phase_of(Phase::Active, Stimulus::Stop), Phase::Stopping);
    }

    #[test]
    fn reload_is_sighup() {
        assert_eq!(
            step(Phase::Disabled, Stimulus::Reload),
            step(Phase::Disabled, Stimulus::Sighup)
        );
        assert_eq!(
            effects_of(Phase::Disabled, Stimulus::Reload),
            vec![Effect::RevalidateOnly]
        );
        assert_eq!(
            effects_of(Phase::Inactive, Stimulus::Reload),
            vec![Effect::AttemptActivation]
        );
        assert_eq!(
            effects_of(Phase::Active, Stimulus::Reload),
            vec![Effect::PolicyTransaction, Effect::EngineCandidateSwitch]
        );
        assert!(effects_of(Phase::Activating, Stimulus::Reload).is_empty());
    }

    #[test]
    fn capture_side_drift_from_active_does_not_freeze() {
        let stepped = step(Phase::Active, Stimulus::CaptureSideDrift);
        assert_eq!(stepped.phase, Phase::Active);
        assert_eq!(stepped.effects, vec![Effect::ReattachCaptureLocally]);
        assert!(!freezes_capture(&stepped.effects));
    }

    #[test]
    fn core_drift_from_active_freezes_first() {
        let stepped = step(Phase::Active, Stimulus::CoreDrift);
        assert_eq!(stepped.phase, Phase::Activating);
        assert_eq!(
            stepped.effects,
            vec![Effect::PublishInactive, Effect::RunPendingConvergence]
        );
        assert!(freezes_capture(&stepped.effects));
    }

    #[test]
    fn last_iface_gone_leaves_active() {
        let last = step(
            Phase::Active,
            Stimulus::InterfaceGone {
                last_active_iface: true,
            },
        );
        assert_eq!(last.phase, Phase::Inactive);
        assert!(freezes_capture(&last.effects));
        let rest = step(
            Phase::Active,
            Stimulus::InterfaceGone {
                last_active_iface: false,
            },
        );
        assert_eq!(rest.phase, Phase::Active);
        assert!(!freezes_capture(&rest.effects));
    }

    #[test]
    fn address_change_leaves_active() {
        let stepped = step(Phase::Active, Stimulus::AddressChange);
        assert_eq!(stepped.phase, Phase::Active);
        assert_eq!(stepped.effects, vec![Effect::UpdateSelfAddresses]);
        assert!(!freezes_capture(&stepped.effects));
    }

    #[test]
    fn policy_events_leave_active() {
        assert_eq!(
            phase_of(Phase::Active, Stimulus::FluxTomlChanged),
            Phase::Active
        );
        assert!(!freezes_capture(&effects_of(
            Phase::Active,
            Stimulus::FluxTomlChanged
        )));
        assert_eq!(
            effects_of(Phase::Active, Stimulus::PackagesChanged),
            vec![Effect::ReparseThenPolicy]
        );
        assert_eq!(
            effects_of(Phase::Active, Stimulus::TemplateOrListChanged),
            vec![Effect::RegenerateThenSwitch]
        );
    }

    #[test]
    fn ssid_pause_and_resume() {
        let pause = step(Phase::Active, Stimulus::SsidPause);
        assert_eq!(pause.phase, Phase::Paused);
        assert!(freezes_capture(&pause.effects));
        assert_eq!(
            step(Phase::Paused, Stimulus::SsidResume),
            with(Phase::Inactive, &[Effect::AttemptActivation])
        );
        assert!(effects_of(Phase::Active, Stimulus::SsidResume).is_empty());
    }

    #[test]
    fn engine_exit_and_faults() {
        assert_eq!(
            effects_of(Phase::Disabled, Stimulus::EngineExited),
            vec![Effect::IgnoreUnexpected]
        );
        assert_eq!(
            phase_of(Phase::Stopping, Stimulus::EngineExited),
            Phase::Disabled
        );
        assert_eq!(
            effects_of(Phase::Inactive, Stimulus::EngineExited),
            vec![Effect::RestartWithBackoff]
        );
        let from_active = step(Phase::Active, Stimulus::EngineExited);
        assert_eq!(from_active.phase, Phase::Inactive);
        assert!(freezes_capture(&from_active.effects));
        assert_eq!(
            effects_of(Phase::Inactive, Stimulus::CurrentGenerationFault),
            vec![Effect::ClearLatchOnly]
        );
        let fault = step(Phase::Active, Stimulus::CurrentGenerationFault);
        assert_eq!(fault.phase, Phase::Inactive);
        assert!(freezes_capture(&fault.effects));
        assert_eq!(
            effects_of(Phase::Active, Stimulus::StaleOrDuplicateFault),
            vec![Effect::ClearLatchOnly]
        );
        assert!(!freezes_capture(&effects_of(
            Phase::Active,
            Stimulus::StaleOrDuplicateFault
        )));
    }

    #[test]
    fn timers() {
        assert!(effects_of(Phase::Disabled, Stimulus::DebounceExpired).is_empty());
        assert_eq!(
            effects_of(Phase::Active, Stimulus::DebounceExpired),
            vec![Effect::RunPendingConvergence]
        );
        assert_eq!(
            effects_of(Phase::Inactive, Stimulus::BackoffExpired),
            vec![Effect::RetryActivation]
        );
        assert_eq!(
            effects_of(Phase::Activating, Stimulus::ReadinessBackoff),
            vec![Effect::RecheckSockDiag]
        );
    }

    #[test]
    fn completions_close_the_machine() {
        assert_eq!(
            phase_of(Phase::Activating, Stimulus::ActivationCommitted),
            Phase::Active
        );
        assert_eq!(
            step(Phase::Activating, Stimulus::ActivationFailed),
            with(Phase::Inactive, &[Effect::PublishInactive])
        );
        assert_eq!(
            phase_of(Phase::Stopping, Stimulus::EngineStopped),
            Phase::Disabled
        );
        assert_eq!(
            effects_of(Phase::Active, Stimulus::ActivationCommitted),
            vec![Effect::IgnoreUnexpected]
        );
        assert_eq!(
            effects_of(Phase::Inactive, Stimulus::EngineStopped),
            vec![Effect::IgnoreUnexpected]
        );
    }

    #[test]
    fn activating_queues_config_events() {
        assert!(effects_of(Phase::Activating, Stimulus::Reload).is_empty());
        assert!(effects_of(Phase::Activating, Stimulus::FluxTomlChanged).is_empty());
        assert!(effects_of(Phase::Activating, Stimulus::NewInterface).is_empty());
    }

    #[test]
    fn observe_matches_committed_flags() {
        let inactive = Observation {
            disable_present: false,
            shutdown: false,
            ssid_paused: false,
            engine_present: false,
            dataplane_active: false,
            awaiting_commit: false,
            convergence_busy: false,
        };
        assert_eq!(Phase::observe(inactive), Phase::Inactive);
        assert_eq!(
            Phase::observe(Observation {
                disable_present: true,
                ..inactive
            }),
            Phase::Disabled
        );
        assert_eq!(
            Phase::observe(Observation {
                disable_present: true,
                engine_present: true,
                ..inactive
            }),
            Phase::Stopping
        );
        assert_eq!(
            Phase::observe(Observation {
                ssid_paused: true,
                ..inactive
            }),
            Phase::Paused
        );
        assert_eq!(
            Phase::observe(Observation {
                engine_present: true,
                awaiting_commit: true,
                ..inactive
            }),
            Phase::Activating
        );
        assert_eq!(
            Phase::observe(Observation {
                engine_present: true,
                dataplane_active: true,
                ..inactive
            }),
            Phase::Active
        );
    }

    #[test]
    fn project_is_the_single_view() {
        assert_eq!(
            project(Phase::Active, None),
            CommittedView {
                state: State::Active,
                display: DisplayKind::Running,
                engine_running: true,
            }
        );
        assert_eq!(project(Phase::Disabled, None).state, State::Disabled);
        assert_eq!(
            project(Phase::Stopping, None).display,
            DisplayKind::Stopping
        );
        assert_eq!(project(Phase::Paused, None).display, DisplayKind::Paused);
        assert_eq!(
            project(Phase::Inactive, None).display,
            DisplayKind::Starting
        );
        assert_eq!(
            project(Phase::Inactive, Some("engine_exited")).display,
            DisplayKind::Failed
        );
        assert!(!project(Phase::Activating, None).engine_running);
    }

    #[test]
    fn generations_are_a_single_owner() {
        let mut gens = Generations::new();
        assert_eq!(gens.committed(), 0);
        assert_eq!(gens.allocate(), 1);
        assert_eq!(gens.allocate(), 2);
        gens.commit(2);
        assert_eq!(gens.committed(), 2);
        assert!(gens.fault_is_current(2, Some(2)));
        assert!(!gens.fault_is_current(1, Some(2)));
        assert!(!gens.fault_is_current(2, Some(1)));
        assert!(!gens.fault_is_current(2, None));
    }

    const ALL_PHASES: [Phase; 6] = [
        Phase::Disabled,
        Phase::Stopping,
        Phase::Paused,
        Phase::Inactive,
        Phase::Activating,
        Phase::Active,
    ];

    #[test]
    fn capture_side_drift_never_publishes_inactive() {
        for phase in ALL_PHASES {
            assert!(
                !freezes_capture(&effects_of(phase, Stimulus::CaptureSideDrift)),
                "{phase:?} capture-side drift must not freeze capture"
            );
        }
    }

    #[test]
    fn core_drift_from_non_active_does_not_invent_a_cutover() {
        for phase in [
            Phase::Disabled,
            Phase::Stopping,
            Phase::Paused,
            Phase::Inactive,
            Phase::Activating,
        ] {
            assert!(
                !effects_of(phase, Stimulus::CoreDrift).contains(&Effect::PublishInactive),
                "{phase:?}"
            );
        }
    }

    #[test]
    fn remaining_table_cells() {
        assert!(effects_of(Phase::Disabled, Stimulus::NewInterface).is_empty());
        assert_eq!(
            effects_of(Phase::Inactive, Stimulus::NewInterface),
            vec![Effect::ReevaluateAdmission]
        );
        assert_eq!(
            effects_of(Phase::Active, Stimulus::NetlinkOverrun),
            vec![Effect::FullRedump]
        );
        assert!(effects_of(Phase::Disabled, Stimulus::NetlinkOverrun).is_empty());
        assert_eq!(
            effects_of(Phase::Inactive, Stimulus::AddressChange),
            vec![Effect::UpdateSelfAddresses]
        );
        assert_eq!(
            effects_of(Phase::Paused, Stimulus::SsidPause),
            stay(Phase::Paused).effects
        );
        assert_eq!(
            phase_of(Phase::Inactive, Stimulus::SsidPause),
            Phase::Paused
        );
        assert_eq!(
            effects_of(Phase::Disabled, Stimulus::PackagesChanged),
            Vec::<Effect>::new()
        );
        assert_eq!(
            effects_of(Phase::Inactive, Stimulus::CaptureSideDrift),
            vec![Effect::RunPendingConvergence]
        );
        assert_eq!(
            step(Phase::Disabled, Stimulus::Enable).phase,
            Phase::Inactive
        );
        assert!(effects_of(Phase::Stopping, Stimulus::Enable).is_empty());
    }

    #[test]
    fn section_26_absent_combo_is_ignore() {
        assert_eq!(
            effects_of(Phase::Active, Stimulus::Bootstrap),
            vec![Effect::IgnoreUnexpected]
        );
        assert_eq!(
            effects_of(Phase::Disabled, Stimulus::EngineExited),
            vec![Effect::IgnoreUnexpected]
        );
    }
}
