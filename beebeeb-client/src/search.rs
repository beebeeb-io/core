use std::{collections::BTreeMap, sync::RwLock};

use tokio::sync::broadcast;

use crate::files::FileRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub is_folder: bool,
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchUpdate {
    pub revision: u64,
}

struct SearchState {
    revision: u64,
    records: BTreeMap<String, FileRecord>,
}

pub struct SearchService {
    state: RwLock<SearchState>,
    updates: broadcast::Sender<SearchUpdate>,
}

impl SearchService {
    pub fn new(capacity: usize) -> Self {
        let (updates, _) = broadcast::channel(capacity.max(1));
        Self {
            state: RwLock::new(SearchState {
                revision: 0,
                records: BTreeMap::new(),
            }),
            updates,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SearchUpdate> {
        self.updates.subscribe()
    }

    pub fn upsert(&self, record: FileRecord) {
        if let Ok(mut state) = self.state.write() {
            state.records.insert(record.id.clone(), record);
            state.revision = state.revision.saturating_add(1);
            let _ = self.updates.send(SearchUpdate {
                revision: state.revision,
            });
        }
    }

    pub fn remove(&self, id: &str) {
        if let Ok(mut state) = self.state.write()
            && state.records.remove(id).is_some()
        {
            state.revision = state.revision.saturating_add(1);
            let _ = self.updates.send(SearchUpdate {
                revision: state.revision,
            });
        }
    }

    pub fn rebuild(&self, records: impl IntoIterator<Item = FileRecord>) {
        if let Ok(mut state) = self.state.write() {
            state.records = records.into_iter().map(|record| (record.id.clone(), record)).collect();
            state.revision = state.revision.saturating_add(1);
            let _ = self.updates.send(SearchUpdate {
                revision: state.revision,
            });
        }
    }

    pub fn clear(&self) {
        if let Ok(mut state) = self.state.write() {
            state.records.clear();
            state.revision = state.revision.saturating_add(1);
            let _ = self.updates.send(SearchUpdate {
                revision: state.revision,
            });
        }
    }

    pub fn query(&self, query: &str) -> Vec<SearchResult> {
        let needle = query.to_lowercase();
        let Ok(state) = self.state.read() else {
            return Vec::new();
        };
        state
            .records
            .values()
            .filter(|record| record.name.to_lowercase().contains(&needle))
            .map(|record| SearchResult {
                id: record.id.clone(),
                name: record.name.clone(),
                parent_id: record.parent_id.clone(),
                is_folder: record.is_folder,
                mime_type: record.mime_type.clone(),
            })
            .collect()
    }
}

pub fn names<'a>(
    nodes: impl IntoIterator<Item = &'a beebeeb_core::sync::TreeNode>,
    query: &str,
) -> Vec<&'a beebeeb_core::sync::TreeNode> {
    let query = query.to_lowercase();
    nodes
        .into_iter()
        .filter(|node| node.name.to_lowercase().contains(&query))
        .collect()
}
