use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use anyhow::Result;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

use crate::halo_protocol::punch::{PunchPacket, encode_punch, parse_punch};

/// Mini-MagicSock wrapping Quinn's `AsyncUdpSocket`.
///
/// - `poll_recv`: steals incoming `HALO_PUNCH` datagrams onto a channel and forwards
///   all other datagrams (QUIC/MoQ) untouched to Quinn.
/// - `ThiefHandle::punch_peer`: sends `HALO_PUNCH` datagrams out of the exact same
///   UDP socket to open stateful IPv6 firewalls.
pub struct ThiefSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    punch_tx: mpsc::UnboundedSender<PunchPacket>,
}

impl fmt::Debug for ThiefSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThiefSocket")
            .field("inner", &self.inner)
            .finish()
    }
}

/// Control handle paired with a [`ThiefSocket`] to send `HALO_PUNCH` packets and
/// receive intercepted punches.
pub struct ThiefHandle {
    socket: Arc<OnceLock<Arc<dyn AsyncUdpSocket>>>,
    punch_rx: mpsc::UnboundedReceiver<PunchPacket>,
}

/// Create a `(socket_wrapper_fn, ThiefHandle)` pair ready for
/// `moq_native_ietf::quic::Config::with_socket_wrapper`.
pub fn thief_socket_pair() -> (
    impl Fn(Arc<dyn AsyncUdpSocket>) -> Arc<dyn AsyncUdpSocket> + Send + Sync + 'static,
    ThiefHandle,
) {
    let (punch_tx, punch_rx) = mpsc::unbounded_channel();
    let socket = Arc::new(OnceLock::new());
    let slot = socket.clone();

    let wrapper = move |inner: Arc<dyn AsyncUdpSocket>| -> Arc<dyn AsyncUdpSocket> {
        let _ = slot.set(inner.clone());
        Arc::new(ThiefSocket {
            inner,
            punch_tx: punch_tx.clone(),
        })
    };

    (wrapper, ThiefHandle { socket, punch_rx })
}

impl ThiefHandle {
    /// Send a `HALO_PUNCH` datagram to `target` from the same UDP socket Quinn uses.
    pub async fn punch_peer(&self, target: SocketAddr, node_id: [u8; 32]) -> Result<()> {
        let sock = self
            .socket
            .get()
            .ok_or_else(|| anyhow::anyhow!("ThiefSocket is not attached to a QUIC endpoint yet"))?
            .clone();
        let payload = encode_punch(&node_id);
        let transmit = Transmit {
            destination: target,
            ecn: None,
            contents: &payload,
            segment_size: None,
            src_ip: None,
        };
        let mut poller = sock.clone().create_io_poller();
        loop {
            match sock.try_send(&transmit) {
                Ok(()) => {
                    tracing::debug!(%target, "sent HALO_PUNCH");
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)).await?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Receive the next intercepted `HALO_PUNCH` datagram.
    pub async fn recv_punch(&mut self) -> Option<PunchPacket> {
        self.punch_rx.recv().await
    }
}

impl AsyncUdpSocket for ThiefSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };

            let mut write_idx = 0;
            for i in 0..n {
                let mut m = meta[i];
                if m.len == 0 {
                    continue;
                }

                let stride = m.stride.max(1);
                if m.len <= stride {
                    // Single datagram (common path)
                    if let Some(punch) = parse_punch(m.addr, &bufs[i][..m.len]) {
                        tracing::debug!(from = %punch.from, "intercepted HALO_PUNCH");
                        let _ = self.punch_tx.send(punch);
                        continue;
                    }
                } else {
                    // UDP GRO coalesced multiple segments into bufs[i][..m.len]
                    let mut kept = 0usize;
                    let mut offset = 0usize;
                    while offset < m.len {
                        let end = (offset + stride).min(m.len);
                        if let Some(punch) = parse_punch(m.addr, &bufs[i][offset..end]) {
                            tracing::debug!(from = %punch.from, "intercepted HALO_PUNCH");
                            let _ = self.punch_tx.send(punch);
                        } else {
                            if kept != offset {
                                bufs[i].copy_within(offset..end, kept);
                            }
                            kept += end - offset;
                        }
                        offset = end;
                    }
                    if kept == 0 {
                        continue;
                    }
                    m.len = kept;
                }

                if write_idx != i {
                    let (head, tail) = bufs.split_at_mut(i);
                    head[write_idx][..m.len].copy_from_slice(&tail[0][..m.len]);
                }
                meta[write_idx] = m;
                write_idx += 1;
            }

            if write_idx > 0 {
                return Poll::Ready(Ok(write_idx));
            }
            // All datagrams in this batch were HALO_PUNCH; poll again so we never return Ok(0) to Quinn.
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
