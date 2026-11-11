use beebeeb_core::chunk_stream::{VersionCounterStatus, check_version_counter};

use crate::{EngineEvent, EngineEvents};

pub use beebeeb_transfer::{DownloadOutcome, download};

pub fn observe_version_counter(
    events: &EngineEvents,
    file_id: &str,
    observed: u64,
    remembered_highest: Option<u64>,
) -> VersionCounterStatus {
    let status = check_version_counter(observed, remembered_highest);
    if status == VersionCounterStatus::Rollback {
        events.emit(EngineEvent::VersionRollback {
            file_id: file_id.to_owned(),
            observed,
            highest: remembered_highest.unwrap_or(observed),
        });
    }
    status
}
