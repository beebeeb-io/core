pub use beebeeb_transfer::background::{
    BackgroundFailure, BackgroundGrant, BackgroundRestartPlan, BackgroundRestore, BackgroundUploadPlanner, SignOutPlan,
    StageProgress, TransferFinished, TransferRequest, UploadSourceIdentity,
};
pub use beebeeb_transfer::upload::{UploadOutcome, UploadSession, upload};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Offline,
    Cellular,
    WiFi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferRule {
    pub wifi_only: bool,
}

impl TransferRule {
    pub fn allows(self, network: NetworkKind) -> bool {
        matches!(network, NetworkKind::WiFi) || (!self.wifi_only && matches!(network, NetworkKind::Cellular))
    }
}
