use futures_util::sink::Sink;
use futures_util::stream::Stream;
use sl_mpc_mate::coord::{MessageSendError, Relay};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, Notify};

pub struct ChannelRelayConn {
    pub rx: mpsc::Receiver<Vec<u8>>,
    pub tx: mpsc::UnboundedSender<Vec<u8>>,
    pub round_complete: Arc<Notify>,
}

impl ChannelRelayConn {
    pub fn new(rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::UnboundedSender<Vec<u8>>) -> (Self, Arc<Notify>) {
        let notify = Arc::new(Notify::new());
        let conn = Self { rx, tx, round_complete: notify.clone() };
        (conn, notify)
    }
}

impl Stream for ChannelRelayConn {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Pending => {
                self.round_complete.notify_one();
                Poll::Pending
            }
            other => other,
        }
    }
}

impl Sink<Vec<u8>> for ChannelRelayConn {
    type Error = MessageSendError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.get_mut().tx.send(item).map_err(|_| MessageSendError)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Unpin for ChannelRelayConn {}

impl Relay for ChannelRelayConn {}
