//! Pure §26 lifecycle: phases, stimuli, commands, and the status projection.
//!
//! The daemon's epoll loop is an adapter over [`plan`]: it decodes events,
//! asks this module what to do, and executes the returned [`Command`]s.
//! Illegal combinations of disable / engine / dataplane flags are not
//! representable as a [`Phase`]. The JSON `State` and the `module.prop` line
//! are both projections of one [`CommittedView`] (blueprint §10.1, §26,
//! §27.1.3).

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

/// A userspace action [`plan`] asks the adapter to perform. No syscalls here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
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

/// Identity of one command in a boot. Completions that carry a stale id must
/// not commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandId(pub u64);

/// One adapter action with an identity so a late completion cannot commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command {
    /// Monotonic id assigned by [`plan`].
    pub id: CommandId,
    /// What the adapter should do.
    pub kind: CommandKind,
}

/// Planner memory: the observed [`Phase`] and the next command id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Model {
    /// Last observed or table-advanced phase.
    pub phase: Phase,
    next_id: u64,
}

impl Model {
    /// Start of a boot. Phase is reconstructed from [`Observation`] after I/O.
    pub fn new(phase: Phase) -> Self {
        Self { phase, next_id: 1 }
    }
}

/// Result of one [`step`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Phase after the stimulus.
    pub phase: Phase,
    /// Adapter actions, in order. Empty means "no userspace work".
    pub commands: Vec<CommandKind>,
}

fn stay(phase: Phase) -> Step {
    Step {
        phase,
        commands: Vec::new(),
    }
}

fn with(phase: Phase, commands: &[CommandKind]) -> Step {
    Step {
        phase,
        commands: commands.to_vec(),
    }
}

fn unexpected(phase: Phase) -> Step {
    with(phase, &[CommandKind::IgnoreUnexpected])
}

/// Advance the lifecycle. Combinations absent from §26 yield
/// [`CommandKind::IgnoreUnexpected`] and leave the phase unchanged.
pub fn step(phase: Phase, stimulus: Stimulus) -> Step {
    match (phase, stimulus) {
        (_, Stimulus::Status | Stimulus::Check) => stay(phase),

        (Phase::Disabled | Phase::Stopping, Stimulus::Bootstrap) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::Bootstrap) => {
            with(phase, &[CommandKind::AttemptActivation])
        }
        (Phase::Activating | Phase::Active, Stimulus::Bootstrap) => unexpected(phase),

        (Phase::Disabled, Stimulus::Enable) => {
            with(Phase::Inactive, &[CommandKind::AttemptActivation])
        }
        (
            Phase::Stopping | Phase::Inactive | Phase::Paused | Phase::Activating | Phase::Active,
            Stimulus::Enable,
        ) => stay(phase),

        (Phase::Disabled | Phase::Stopping, Stimulus::Disable) => stay(phase),
        (Phase::Inactive | Phase::Paused | Phase::Activating, Stimulus::Disable) => {
            with(Phase::Stopping, &[CommandKind::StopEngine])
        }
        (Phase::Active, Stimulus::Disable) => with(
            Phase::Stopping,
            &[CommandKind::PublishInactive, CommandKind::StopEngine],
        ),

        (Phase::Disabled | Phase::Stopping, Stimulus::Reload | Stimulus::Sighup) => {
            with(phase, &[CommandKind::RevalidateOnly])
        }
        (Phase::Inactive | Phase::Paused, Stimulus::Reload | Stimulus::Sighup) => {
            with(phase, &[CommandKind::AttemptActivation])
        }
        (Phase::Activating, Stimulus::Reload | Stimulus::Sighup) => stay(phase),
        (Phase::Active, Stimulus::Reload | Stimulus::Sighup) => with(
            Phase::Active,
            &[
                CommandKind::PolicyTransaction,
                CommandKind::EngineCandidateSwitch,
            ],
        ),

        (Phase::Disabled | Phase::Stopping, Stimulus::Stop | Stimulus::Sigterm) => {
            with(phase, &[CommandKind::ExitProcess])
        }
        (
            Phase::Inactive | Phase::Paused | Phase::Activating | Phase::Active,
            Stimulus::Stop | Stimulus::Sigterm,
        ) => with(
            Phase::Stopping,
            &[
                CommandKind::PublishInactive,
                CommandKind::StopEngine,
                CommandKind::ExitProcess,
            ],
        ),

        (Phase::Disabled | Phase::Stopping, Stimulus::NewInterface) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::NewInterface) => {
            with(phase, &[CommandKind::ReevaluateAdmission])
        }
        (Phase::Activating, Stimulus::NewInterface) => stay(phase),
        (Phase::Active, Stimulus::NewInterface) => {
            with(Phase::Active, &[CommandKind::AdmitAndAttach])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::InterfaceGone { .. }) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::InterfaceGone { .. }) => {
            with(phase, &[CommandKind::ReevaluateAdmission])
        }
        (Phase::Activating, Stimulus::InterfaceGone { .. }) => stay(phase),
        (
            Phase::Active,
            Stimulus::InterfaceGone {
                last_active_iface: true,
            },
        ) => with(
            Phase::Inactive,
            &[CommandKind::PublishInactive, CommandKind::ExcludeInterface],
        ),
        (
            Phase::Active,
            Stimulus::InterfaceGone {
                last_active_iface: false,
            },
        ) => with(Phase::Active, &[CommandKind::ExcludeInterface]),

        (Phase::Disabled | Phase::Stopping, Stimulus::AddressChange) => stay(phase),
        (Phase::Inactive | Phase::Paused | Phase::Activating, Stimulus::AddressChange) => {
            with(phase, &[CommandKind::UpdateSelfAddresses])
        }
        (Phase::Active, Stimulus::AddressChange) => {
            with(Phase::Active, &[CommandKind::UpdateSelfAddresses])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::CaptureSideDrift) => stay(phase),
        (Phase::Inactive | Phase::Paused | Phase::Activating, Stimulus::CaptureSideDrift) => {
            with(phase, &[CommandKind::RunPendingConvergence])
        }
        (Phase::Active, Stimulus::CaptureSideDrift) => {
            with(Phase::Active, &[CommandKind::ReattachCaptureLocally])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::CoreDrift) => stay(phase),
        (Phase::Inactive | Phase::Paused | Phase::Activating, Stimulus::CoreDrift) => {
            with(phase, &[CommandKind::RunPendingConvergence])
        }
        (Phase::Active, Stimulus::CoreDrift) => with(
            Phase::Activating,
            &[
                CommandKind::PublishInactive,
                CommandKind::RunPendingConvergence,
            ],
        ),

        (Phase::Disabled | Phase::Stopping, Stimulus::NetlinkOverrun) => stay(phase),
        (_, Stimulus::NetlinkOverrun) => with(phase, &[CommandKind::FullRedump]),

        (Phase::Disabled | Phase::Stopping, Stimulus::FluxTomlChanged) => {
            with(phase, &[CommandKind::RevalidateOnly])
        }
        (Phase::Inactive | Phase::Paused, Stimulus::FluxTomlChanged) => {
            with(phase, &[CommandKind::AttemptActivation])
        }
        (Phase::Activating, Stimulus::FluxTomlChanged) => stay(phase),
        (Phase::Active, Stimulus::FluxTomlChanged) => {
            with(Phase::Active, &[CommandKind::PolicyTransaction])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::TemplateOrListChanged) => {
            with(phase, &[CommandKind::RevalidateOnly])
        }
        (Phase::Inactive | Phase::Paused, Stimulus::TemplateOrListChanged) => {
            with(phase, &[CommandKind::AttemptActivation])
        }
        (Phase::Activating, Stimulus::TemplateOrListChanged) => stay(phase),
        (Phase::Active, Stimulus::TemplateOrListChanged) => {
            with(Phase::Active, &[CommandKind::RegenerateThenSwitch])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::PackagesChanged) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::PackagesChanged) => {
            with(phase, &[CommandKind::ReparseThenPolicy])
        }
        (Phase::Activating, Stimulus::PackagesChanged) => stay(phase),
        (Phase::Active, Stimulus::PackagesChanged) => {
            with(Phase::Active, &[CommandKind::ReparseThenPolicy])
        }

        (Phase::Disabled | Phase::Stopping, Stimulus::SsidPause) => stay(phase),
        (Phase::Inactive | Phase::Paused, Stimulus::SsidPause) => stay(Phase::Paused),
        (Phase::Activating | Phase::Active, Stimulus::SsidPause) => with(
            Phase::Paused,
            &[CommandKind::PublishInactive, CommandKind::StopEngine],
        ),

        (Phase::Paused, Stimulus::SsidResume) => {
            with(Phase::Inactive, &[CommandKind::AttemptActivation])
        }
        (_, Stimulus::SsidResume) => stay(phase),

        (Phase::Disabled, Stimulus::EngineExited) => unexpected(phase),
        (Phase::Stopping, Stimulus::EngineExited) => stay(Phase::Disabled),
        (Phase::Inactive | Phase::Paused, Stimulus::EngineExited) => {
            with(phase, &[CommandKind::RestartWithBackoff])
        }
        (Phase::Activating | Phase::Active, Stimulus::EngineExited) => with(
            Phase::Inactive,
            &[
                CommandKind::PublishInactive,
                CommandKind::RestartWithBackoff,
            ],
        ),

        (Phase::Disabled, Stimulus::CurrentGenerationFault) => unexpected(phase),
        (Phase::Stopping | Phase::Inactive | Phase::Paused, Stimulus::CurrentGenerationFault) => {
            with(phase, &[CommandKind::ClearLatchOnly])
        }
        (Phase::Activating | Phase::Active, Stimulus::CurrentGenerationFault) => with(
            Phase::Inactive,
            &[
                CommandKind::PublishInactive,
                CommandKind::RestartWithBackoff,
            ],
        ),

        (_, Stimulus::StaleOrDuplicateFault) => with(phase, &[CommandKind::ClearLatchOnly]),

        (Phase::Disabled | Phase::Stopping, Stimulus::DebounceExpired) => stay(phase),
        (_, Stimulus::DebounceExpired) => with(phase, &[CommandKind::RunPendingConvergence]),

        (Phase::Disabled | Phase::Stopping, Stimulus::BackoffExpired) => stay(phase),
        (_, Stimulus::BackoffExpired) => with(phase, &[CommandKind::RetryActivation]),

        (Phase::Disabled | Phase::Stopping, Stimulus::ReadinessBackoff) => stay(phase),
        (_, Stimulus::ReadinessBackoff) => with(phase, &[CommandKind::RecheckSockDiag]),

        (Phase::Activating, Stimulus::ActivationCommitted) => stay(Phase::Active),
        (Phase::Activating, Stimulus::ActivationFailed) => {
            with(Phase::Inactive, &[CommandKind::PublishInactive])
        }
        (_, Stimulus::ActivationCommitted | Stimulus::ActivationFailed) => unexpected(phase),

        (Phase::Stopping, Stimulus::EngineStopped) => stay(Phase::Disabled),
        (_, Stimulus::EngineStopped) => unexpected(phase),
    }
}

/// Assign identities to [`step`] output so a late completion cannot commit.
pub fn plan(mut model: Model, stimulus: Stimulus) -> (Model, Vec<Command>) {
    let stepped = step(model.phase, stimulus);
    model.phase = stepped.phase;
    let commands = stepped
        .commands
        .into_iter()
        .map(|kind| {
            let id = CommandId(model.next_id);
            model.next_id = model.next_id.saturating_add(1);
            Command { id, kind }
        })
        .collect();
    (model, commands)
}

/// True when `commands` would freeze capture. Capture-side drift MUST NOT.
pub fn freezes_capture(commands: &[CommandKind]) -> bool {
    commands.contains(&CommandKind::PublishInactive)
}

impl CommandKind {
    /// True when the adapter should run the shared dataplane/engine executor.
    /// Freeze, stop, exit, latch-clear and SOCK_DIAG recheck are not this.
    pub fn needs_converge(self) -> bool {
        matches!(
            self,
            Self::AttemptActivation
                | Self::PolicyTransaction
                | Self::EngineCandidateSwitch
                | Self::ReevaluateAdmission
                | Self::AdmitAndAttach
                | Self::ExcludeInterface
                | Self::UpdateSelfAddresses
                | Self::ReattachCaptureLocally
                | Self::FullRedump
                | Self::RegenerateThenSwitch
                | Self::ReparseThenPolicy
                | Self::RunPendingConvergence
                | Self::RetryActivation
        )
    }
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

    fn commands_of(phase: Phase, stimulus: Stimulus) -> Vec<CommandKind> {
        step(phase, stimulus).commands
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
            commands_of(Phase::Inactive, Stimulus::Bootstrap),
            vec![CommandKind::AttemptActivation]
        );
        assert_eq!(
            commands_of(Phase::Active, Stimulus::Bootstrap),
            vec![CommandKind::IgnoreUnexpected]
        );
    }

    #[test]
    fn enable_disable_stop() {
        assert_eq!(
            step(Phase::Disabled, Stimulus::Enable),
            with(Phase::Inactive, &[CommandKind::AttemptActivation])
        );
        assert!(commands_of(Phase::Inactive, Stimulus::Enable).is_empty());
        assert!(commands_of(Phase::Active, Stimulus::Enable).is_empty());
        assert!(commands_of(Phase::Disabled, Stimulus::Disable).is_empty());
        assert_eq!(
            step(Phase::Inactive, Stimulus::Disable),
            with(Phase::Stopping, &[CommandKind::StopEngine])
        );
        assert_eq!(
            step(Phase::Active, Stimulus::Disable),
            with(
                Phase::Stopping,
                &[CommandKind::PublishInactive, CommandKind::StopEngine]
            )
        );
        assert_eq!(
            commands_of(Phase::Disabled, Stimulus::Stop),
            vec![CommandKind::ExitProcess]
        );
        assert!(commands_of(Phase::Active, Stimulus::Stop).contains(&CommandKind::PublishInactive));
        assert_eq!(phase_of(Phase::Active, Stimulus::Stop), Phase::Stopping);
    }

    #[test]
    fn reload_is_sighup() {
        assert_eq!(
            step(Phase::Disabled, Stimulus::Reload),
            step(Phase::Disabled, Stimulus::Sighup)
        );
        assert_eq!(
            commands_of(Phase::Disabled, Stimulus::Reload),
            vec![CommandKind::RevalidateOnly]
        );
        assert_eq!(
            commands_of(Phase::Inactive, Stimulus::Reload),
            vec![CommandKind::AttemptActivation]
        );
        assert_eq!(
            commands_of(Phase::Active, Stimulus::Reload),
            vec![
                CommandKind::PolicyTransaction,
                CommandKind::EngineCandidateSwitch
            ]
        );
        assert!(commands_of(Phase::Activating, Stimulus::Reload).is_empty());
    }

    #[test]
    fn capture_side_drift_from_active_does_not_freeze() {
        let stepped = step(Phase::Active, Stimulus::CaptureSideDrift);
        assert_eq!(stepped.phase, Phase::Active);
        assert_eq!(stepped.commands, vec![CommandKind::ReattachCaptureLocally]);
        assert!(!freezes_capture(&stepped.commands));
    }

    #[test]
    fn core_drift_from_active_freezes_first() {
        let stepped = step(Phase::Active, Stimulus::CoreDrift);
        assert_eq!(stepped.phase, Phase::Activating);
        assert_eq!(
            stepped.commands,
            vec![
                CommandKind::PublishInactive,
                CommandKind::RunPendingConvergence
            ]
        );
        assert!(freezes_capture(&stepped.commands));
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
        assert!(freezes_capture(&last.commands));
        let rest = step(
            Phase::Active,
            Stimulus::InterfaceGone {
                last_active_iface: false,
            },
        );
        assert_eq!(rest.phase, Phase::Active);
        assert!(!freezes_capture(&rest.commands));
    }

    #[test]
    fn address_change_leaves_active() {
        let stepped = step(Phase::Active, Stimulus::AddressChange);
        assert_eq!(stepped.phase, Phase::Active);
        assert_eq!(stepped.commands, vec![CommandKind::UpdateSelfAddresses]);
        assert!(!freezes_capture(&stepped.commands));
    }

    #[test]
    fn policy_events_leave_active() {
        assert_eq!(
            phase_of(Phase::Active, Stimulus::FluxTomlChanged),
            Phase::Active
        );
        assert!(!freezes_capture(&commands_of(
            Phase::Active,
            Stimulus::FluxTomlChanged
        )));
        assert_eq!(
            commands_of(Phase::Active, Stimulus::PackagesChanged),
            vec![CommandKind::ReparseThenPolicy]
        );
        assert_eq!(
            commands_of(Phase::Active, Stimulus::TemplateOrListChanged),
            vec![CommandKind::RegenerateThenSwitch]
        );
    }

    #[test]
    fn ssid_pause_and_resume() {
        let pause = step(Phase::Active, Stimulus::SsidPause);
        assert_eq!(pause.phase, Phase::Paused);
        assert!(freezes_capture(&pause.commands));
        assert_eq!(
            step(Phase::Paused, Stimulus::SsidResume),
            with(Phase::Inactive, &[CommandKind::AttemptActivation])
        );
        assert!(commands_of(Phase::Active, Stimulus::SsidResume).is_empty());
    }

    #[test]
    fn engine_exit_and_faults() {
        assert_eq!(
            commands_of(Phase::Disabled, Stimulus::EngineExited),
            vec![CommandKind::IgnoreUnexpected]
        );
        assert_eq!(
            phase_of(Phase::Stopping, Stimulus::EngineExited),
            Phase::Disabled
        );
        assert_eq!(
            commands_of(Phase::Inactive, Stimulus::EngineExited),
            vec![CommandKind::RestartWithBackoff]
        );
        let from_active = step(Phase::Active, Stimulus::EngineExited);
        assert_eq!(from_active.phase, Phase::Inactive);
        assert!(freezes_capture(&from_active.commands));
        assert_eq!(
            commands_of(Phase::Inactive, Stimulus::CurrentGenerationFault),
            vec![CommandKind::ClearLatchOnly]
        );
        let fault = step(Phase::Active, Stimulus::CurrentGenerationFault);
        assert_eq!(fault.phase, Phase::Inactive);
        assert!(freezes_capture(&fault.commands));
        assert_eq!(
            commands_of(Phase::Active, Stimulus::StaleOrDuplicateFault),
            vec![CommandKind::ClearLatchOnly]
        );
        assert!(!freezes_capture(&commands_of(
            Phase::Active,
            Stimulus::StaleOrDuplicateFault
        )));
    }

    #[test]
    fn timers() {
        assert!(commands_of(Phase::Disabled, Stimulus::DebounceExpired).is_empty());
        assert_eq!(
            commands_of(Phase::Active, Stimulus::DebounceExpired),
            vec![CommandKind::RunPendingConvergence]
        );
        assert_eq!(
            commands_of(Phase::Inactive, Stimulus::BackoffExpired),
            vec![CommandKind::RetryActivation]
        );
        assert_eq!(
            commands_of(Phase::Activating, Stimulus::ReadinessBackoff),
            vec![CommandKind::RecheckSockDiag]
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
            with(Phase::Inactive, &[CommandKind::PublishInactive])
        );
        assert_eq!(
            phase_of(Phase::Stopping, Stimulus::EngineStopped),
            Phase::Disabled
        );
        assert_eq!(
            commands_of(Phase::Active, Stimulus::ActivationCommitted),
            vec![CommandKind::IgnoreUnexpected]
        );
        assert_eq!(
            commands_of(Phase::Inactive, Stimulus::EngineStopped),
            vec![CommandKind::IgnoreUnexpected]
        );
    }

    #[test]
    fn activating_queues_config_events() {
        assert!(commands_of(Phase::Activating, Stimulus::Reload).is_empty());
        assert!(commands_of(Phase::Activating, Stimulus::FluxTomlChanged).is_empty());
        assert!(commands_of(Phase::Activating, Stimulus::NewInterface).is_empty());
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
                !freezes_capture(&commands_of(phase, Stimulus::CaptureSideDrift)),
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
                !commands_of(phase, Stimulus::CoreDrift).contains(&CommandKind::PublishInactive),
                "{phase:?}"
            );
        }
    }

    #[test]
    fn remaining_table_cells() {
        assert!(commands_of(Phase::Disabled, Stimulus::NewInterface).is_empty());
        assert_eq!(
            commands_of(Phase::Inactive, Stimulus::NewInterface),
            vec![CommandKind::ReevaluateAdmission]
        );
        assert_eq!(
            commands_of(Phase::Active, Stimulus::NetlinkOverrun),
            vec![CommandKind::FullRedump]
        );
        assert!(commands_of(Phase::Disabled, Stimulus::NetlinkOverrun).is_empty());
        assert_eq!(
            commands_of(Phase::Inactive, Stimulus::AddressChange),
            vec![CommandKind::UpdateSelfAddresses]
        );
        assert_eq!(
            commands_of(Phase::Paused, Stimulus::SsidPause),
            stay(Phase::Paused).commands
        );
        assert_eq!(
            phase_of(Phase::Inactive, Stimulus::SsidPause),
            Phase::Paused
        );
        assert_eq!(
            commands_of(Phase::Disabled, Stimulus::PackagesChanged),
            Vec::<CommandKind>::new()
        );
        assert_eq!(
            commands_of(Phase::Inactive, Stimulus::CaptureSideDrift),
            vec![CommandKind::RunPendingConvergence]
        );
        assert_eq!(
            step(Phase::Disabled, Stimulus::Enable).phase,
            Phase::Inactive
        );
        assert!(commands_of(Phase::Stopping, Stimulus::Enable).is_empty());
    }

    #[test]
    fn section_26_absent_combo_is_ignore() {
        assert_eq!(
            commands_of(Phase::Active, Stimulus::Bootstrap),
            vec![CommandKind::IgnoreUnexpected]
        );
        assert_eq!(
            commands_of(Phase::Disabled, Stimulus::EngineExited),
            vec![CommandKind::IgnoreUnexpected]
        );
    }

    #[test]
    fn plan_assigns_monotonic_ids_and_does_not_freeze_on_capture_drift() {
        let (model, commands) = plan(Model::new(Phase::Active), Stimulus::CaptureSideDrift);
        assert_eq!(model.phase, Phase::Active);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].id, CommandId(1));
        assert_eq!(commands[0].kind, CommandKind::ReattachCaptureLocally);
        assert!(!freezes_capture(
            &commands
                .iter()
                .map(|command| command.kind)
                .collect::<Vec<_>>()
        ));
        assert!(CommandKind::ReattachCaptureLocally.needs_converge());
        assert!(!CommandKind::PublishInactive.needs_converge());
        assert!(!CommandKind::ClearLatchOnly.needs_converge());
        let (_, next) = plan(model, Stimulus::Reload);
        assert_eq!(next[0].id, CommandId(2));
        assert_eq!(next[1].id, CommandId(3));
    }
}
