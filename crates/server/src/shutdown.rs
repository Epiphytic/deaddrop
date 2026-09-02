use tokio::sync::watch;

/// Idempotent process-local shutdown trigger.
#[derive(Clone)]
pub struct ShutdownTrigger(watch::Sender<bool>);

/// Cloneable shutdown observation handle.
#[derive(Clone)]
pub struct ShutdownSignal(watch::Receiver<bool>);

pub fn shutdown_channel() -> (ShutdownTrigger, ShutdownSignal) {
    let (sender, receiver) = watch::channel(false);
    (ShutdownTrigger(sender), ShutdownSignal(receiver))
}

impl ShutdownTrigger {
    pub fn trigger(&self) {
        self.0.send_replace(true);
    }
}

impl ShutdownSignal {
    pub fn is_triggered(&self) -> bool {
        *self.0.borrow()
    }

    pub async fn cancelled(&mut self) {
        if self.is_triggered() {
            return;
        }
        while self.0.changed().await.is_ok() {
            if self.is_triggered() {
                return;
            }
        }
    }
}
