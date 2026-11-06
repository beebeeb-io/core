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
}

impl Clone for ClientRuntime {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
        }
    }
}
