use anyhow::Result;
use moq_native_ietf::{quic, reexports::anyhow::Context, tls};
use moq_transport::{serve, session::Subscriber};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::io::AsyncWrite;
use tracing::{Level, event};
use url::Url;

/// Connect to a MoQ publisher over raw QUIC, subscribe to a stream
/// and write the received fMP4 bytes to `output`.
pub async fn subscribe<O>(
    addr: SocketAddr,
    output: O,
    discovery: Option<SocketAddr>,
) -> Result<()>
where
    O: AsyncWrite + Send + Unpin + 'static,
{
    // The TLS config we load disables verification entirely.
    // This way, self-signed certs are valid. We'll take care of TLS later.
    let tls = tls::Args {
        disable_verify: true,
        ..Default::default()
    }
    .load()?;

    // Make a raw QUIC endpoint. We'll bind it to port "0" which means any random (high) ephemeral port
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = UdpSocket::bind(bind).context("UDP bind failed")?;

    if let Some(server) = discovery {
        let observed = crate::halo_core::discovery::discover_external_addr(&socket, server).await?;
        tracing::info!(%observed, "subscriber external address discovered");
    }

    let (thief_wrapper, mut thief) = crate::halo_core::thief_socket::thief_socket_pair();
    let quic_config =
        quic::Config::with_socket(socket, None, tls).with_socket_wrapper(thief_wrapper);
    let endpoint = quic::Endpoint::new(quic_config).context("QUIC endpoint creation failed")?;

    // moqt:// is for raw QUIC, https:// would be for WebTransport
    let url = Url::parse(&format!("moqt://{addr}"))?;
    event!(Level::INFO, "connecting to {url}");

    // Try to connect to the moqt:// url
    let (session, cid, transport) = endpoint
        .client
        .connect(&url, None)
        .await
        .with_context(|| format!("failed to connect"))?;
    event!(Level::INFO, "connected, cid={cid}");

    let (session, subscriber) = Subscriber::connect(session, transport)
        .await
        .context("MoQ setup failed")?;

    let receive = async move {
        // The publisher announces its namespace right after setup. Wait for it, accept it,
        // and subscribe to that namespace.
        let mut announces = subscriber.clone();
        // moq-transport gives us a good abstraction to just fetch the last published namespace
        let mut announced =
            tokio::time::timeout(Duration::from_secs(10), announces.published_namespace())
                .await
                .context("timed out waiting for the publisher to announce a stream")?
                .context("connection closed before the publisher announced a stream")?;
        announced.ok().context("failed to accept the announce")?;

        let namespace = announced.info.namespace.clone();
        tracing::info!(%namespace, "publisher announced stream; receiving");

        let tracks = serve::Tracks::new(namespace);
        let mut media = moq_sub::media::Media::new(subscriber, tracks, output, false).await?;
        let res = media.run().await.context("media error");
        drop(announced); // held until here so the announce stays accepted
        res
    };

    let punch_loop = async move {
        while let Some(punch) = thief.recv_punch().await {
            tracing::info!(from = %punch.from, has_node_id = punch.node_id.is_some(), "received HALO_PUNCH");
        }
        std::future::pending::<Result<()>>().await
    };

    tokio::select! {
        res = session.run() => res.context("session error"),
        res = receive => res,
        res = punch_loop => res,
    }
}
