use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use beebeeb_api::{Answer, Header, Request};
use tokio::sync::Notify;

use crate::{Transport, TransportError, TransportFuture};

#[derive(Clone)]
pub struct ScriptedTransport {
    state: Arc<State>,
}

struct State {
    replies: Mutex<VecDeque<Result<Answer, TransportError>>>,
    requests: Mutex<Vec<Request>>,
    pause: bool,
    sent: AtomicBool,
    released: AtomicBool,
    sent_notify: Notify,
    release_notify: Notify,
}

impl ScriptedTransport {
    pub fn json(status: u16, body: Vec<u8>) -> Self {
        Self::new(
            false,
            Ok(Answer::new(
                status,
                vec![Header::new("Content-Type", "application/json")],
                body,
            )),
        )
    }

    pub fn paused_json(status: u16, body: Vec<u8>) -> Self {
        Self::new(
            true,
            Ok(Answer::new(
                status,
                vec![Header::new("Content-Type", "application/json")],
                body,
            )),
        )
    }

    fn new(pause: bool, reply: Result<Answer, TransportError>) -> Self {
        Self {
            state: Arc::new(State {
                replies: Mutex::new(VecDeque::from([reply])),
                requests: Mutex::new(Vec::new()),
                pause,
                sent: AtomicBool::new(false),
                released: AtomicBool::new(false),
                sent_notify: Notify::new(),
                release_notify: Notify::new(),
            }),
        }
    }

    pub fn fail_next(&self, error: TransportError) {
        if let Ok(mut replies) = self.state.replies.lock() {
            replies.push_front(Err(error));
        }
    }

    pub fn push_json(&self, status: u16, body: Vec<u8>) {
        if let Ok(mut replies) = self.state.replies.lock() {
            replies.push_back(Ok(Answer::new(
                status,
                vec![Header::new("Content-Type", "application/json")],
                body,
            )));
        }
    }

    pub fn respond_next_json(&self, status: u16, body: Vec<u8>) {
        if let Ok(mut replies) = self.state.replies.lock() {
            replies.push_front(Ok(Answer::new(
                status,
                vec![Header::new("Content-Type", "application/json")],
                body,
            )));
        }
    }

    pub fn requests(&self) -> Vec<Request> {
        self.state
            .requests
            .lock()
            .map(|requests| requests.clone())
            .unwrap_or_default()
    }

    pub async fn wait_until_sent(&self) {
        while !self.state.sent.load(Ordering::Acquire) {
            self.state.sent_notify.notified().await;
        }
    }

    pub fn release(&self) {
        self.state.released.store(true, Ordering::Release);
        self.state.release_notify.notify_waiters();
    }

    pub fn request_count(&self) -> usize {
        self.state.requests.lock().map(|requests| requests.len()).unwrap_or(0)
    }
}

impl Transport for ScriptedTransport {
    fn send<'a>(&'a self, request: Request, max_response_bytes: usize) -> TransportFuture<'a> {
        Box::pin(async move {
            self.state
                .requests
                .lock()
                .map_err(|_| TransportError::Network)?
                .push(request);
            self.state.sent.store(true, Ordering::Release);
            self.state.sent_notify.notify_waiters();
            if self.state.pause {
                while !self.state.released.load(Ordering::Acquire) {
                    self.state.release_notify.notified().await;
                }
            }
            let answer = self
                .state
                .replies
                .lock()
                .map_err(|_| TransportError::Network)?
                .pop_front()
                .unwrap_or(Err(TransportError::Network))?;
            if answer.body.len() > max_response_bytes {
                return Err(TransportError::ResponseTooLarge);
            }
            Ok(answer)
        })
    }
}
