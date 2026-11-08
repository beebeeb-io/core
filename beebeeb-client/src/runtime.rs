use std::{future::Future, io, sync::Arc};

pub struct ClientRuntime {
    runtime: Arc<tokio::runtime::Runtime>,
}

impl ClientRuntime {
    #[cfg(feature = "runtime-multi-thread")]
    pub fn multi_thread() -> io::Result<Self> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map(|runtime| Self {
                runtime: Arc::new(runtime),
            })
    }

    pub fn lightweight() -> io::Result<Self> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|runtime| Self {
                runtime: Arc::new(runtime),
            })
    }

    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }

    /// Whether spawned tasks run on their own. On the lightweight runtime
    /// they run only while a `block_on` call is in progress.
    pub fn runs_tasks_alone(&self) -> bool {
        self.runtime.handle().runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
    }
}

impl Clone for ClientRuntime {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ClientRuntime;

    #[test]
    fn only_the_multi_thread_runtime_runs_tasks_alone() {
        assert!(!ClientRuntime::lightweight().unwrap().runs_tasks_alone());
        #[cfg(feature = "runtime-multi-thread")]
        assert!(ClientRuntime::multi_thread().unwrap().runs_tasks_alone());
    }
}
