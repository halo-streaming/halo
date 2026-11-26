use std::io::Cursor;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use local_ip_address::list_afinet_netifas;
use mp4::ReadBox;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::{Notify, broadcast, watch};

use moq_native_ietf::{quic, tls};
use moq_transport::{
    coding::TrackNamespace,
    serve,
    session::{Publisher as MoqPublisher, Transport, transport::Session as TransportSession},
};

const DEFAULT_PORT: u16 = 4443;

// fMP4 (moof + mdat) fragment
// Every subscriber starts video playback at a keyframe (I-frame)
#[derive(Clone)]
struct Fragment {
    data: Bytes,
    keyframe: bool,
}

// We have to convert the mp4 file to fMP4 (fragmented mp4) to serve it over MoQ.
// At first the fmp4 contains "ftyp" and "moov" segments which are file type identifier
// and initialization metadata, respectively.
// Then it is consisting only of "moof" (fragment metadata) and "mdat" (fragment media data).
// The first subscriber will get the ftyp and moov so it can understand how to decode the fMP4,
// however by default the next ones will not get it. So we need a shared state between ffmpeg
// and every subscriber to share the init segment to all subscribers.
struct Hub {
    /// "ftyp" + "moov" set once ffmpeg has produced them
    init: watch::Sender<Option<Bytes>>,
    /// Live fragments in order. "broadcast" distributes each fragment
    /// to independent subscribers
    live: broadcast::Sender<Fragment>,
    /// Signaled when the first subscriber has connected (ffmpeg starts then).
    first_peer: Notify,
}

pub struct Publisher {
    file: PathBuf,
    node_id: [u8; 32],
    server: quic::Server,
    ticket: String,
    thief: crate::halo_core::thief_socket::ThiefHandle,
    _cert_dir: tempfile::TempDir,
}

impl Publisher {
    pub async fn bind(
        file: impl AsRef<Path>,
        node_id: [u8; 32],
        discovery: Option<SocketAddr>,
    ) -> Result<Self> {
        let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT);
        Self::bind_with(file.as_ref(), node_id, bind, None, discovery).await
    }

    async fn bind_with(
        path: &Path,
        node_id: [u8; 32],
        bind: SocketAddr,
        advertise_ip: Option<IpAddr>,
        discovery: Option<SocketAddr>,
    ) -> Result<Self> {
        // Doesn't verify if it's real mp4 tho
        anyhow::ensure!(path.is_file(), "video file not found: {}", path.display());

        let socket =
            UdpSocket::bind(bind).with_context(|| format!("failed to bind UDP socket to {bind}"))?;

        let ip = match (advertise_ip, discovery) {
            (Some(ip), _) => ip,
            (None, Some(server)) => {
                crate::halo_core::discovery::discover_external_addr(&socket, server)
                    .await?
                    .ip()
            }
            (None, None) => IpAddr::V6(detect_publisher_ipv6()?),
        };

        // Generate a temporary self-signed certificate in a temporary directory.
        let dir = tempfile::tempdir().context("failed to create temp dir for certificate")?;
        let (cert, key) = write_self_signed(dir.path())?;

        // Configure TLS arguments (no verification)
        let mut tls_args = tls::Args {
            disable_verify: true,
            ..Default::default()
        };
        tls_args.cert.push(cert);
        tls_args.key.push(key);
        let tls = tls_args.load()?;

        let (thief_wrapper, thief) = crate::halo_core::thief_socket::thief_socket_pair();
        let quic_config =
            quic::Config::with_socket(socket, None, tls).with_socket_wrapper(thief_wrapper);
        let endpoint = quic::Endpoint::new(quic_config)?;

        let server = endpoint.server.context("TLS config missing")?;
        tracing::info!(listen = %server.local_addr()?, file=%path.display(), "publishing, waiting for subscribers");
        let ticket = crate::halo_protocol::node::encode_ticket(&node_id, ip);
        tracing::info!(ticket = %ticket, "publisher join ticket");

        Ok(Self {
            file: path.to_path_buf(),
            node_id,
            server,
            ticket,
            thief,
            _cert_dir: dir,
        })
    }

    pub fn ticket(&self) -> &str {
        &self.ticket
    }

    /// Send a `HALO_PUNCH` UDP datagram from this publisher's QUIC socket to open a firewall pinhole.
    pub async fn punch_peer(&self, target: SocketAddr) -> Result<()> {
        self.thief.punch_peer(target, self.node_id).await
    }

    pub fn thief_mut(&mut self) -> &mut crate::halo_core::thief_socket::ThiefHandle {
        &mut self.thief
    }

    pub async fn run(mut self) -> Result<()> {
        // The init segment is shared for all subscribers so they can decode the stream properly
        let (init, _) = watch::channel(None); // It gets populated when the first subscriber comes
        // Broadcast channel for fragments, so every subscriber can read from it at the same time. Max fragments is 1024 (because why not + audio track)
        let (live, _) = broadcast::channel(1024);
        let hub = Arc::new(Hub {
            init,
            live,
            first_peer: Notify::new(),
        });

        let punch_loop = async {
            while let Some(punch) = self.thief.recv_punch().await {
                tracing::info!(from = %punch.from, has_node_id = punch.node_id.is_some(), "received HALO_PUNCH");
            }
            std::future::pending::<Result<()>>().await
        };

        tokio::select! {
            res = accept_loop(self.server, hub.clone()) => res,
            res = run_ffmpeg(&self.file, hub) => res,
            res = punch_loop => res,
        }
    }
}

/// Accept new subscriber connections.
async fn accept_loop(mut server: quic::Server, hub: Arc<Hub>) -> Result<()> {
    // Hardcoded = not good!
    let name = String::from("shrek");
    // Server accepts connections. When one is recieved:
    while let Some((session, info)) = server.accept().await {
        // Get info for that connection (who is connecting?)
        let quic::ConnInfo {
            id,
            transport,
            remote_address,
            ..
        } = info;
        let hub = hub.clone();
        let name = name.clone();
        // Each connection spawns a thread and we'll serve them the stream data.
        tokio::spawn(async move {
            tracing::info!(peer=%remote_address, cid=%id, "subscriber connected");
            if let Err(err) = serve_peer(session, transport, hub, name).await {
                tracing::warn!(peer=%remote_address, "subscriber session ended: {err:#}");
            }
        });
    }
    Ok(())
}

/// Serve one subscriber with its own broadcast so it always get the init segment (ftyp + moov)
async fn serve_peer(
    session: TransportSession,
    transport: Transport,
    hub: Arc<Hub>,
    name: String,
) -> Result<()> {
    let (session, mut publisher) = MoqPublisher::accept(session, transport)
        .await
        .context("MoQ setup failed")?;

    hub.first_peer.notify_one();

    // Join the live feed before waiting for the init segment, so no keyframe is missed.
    let live = hub.live.subscribe();

    let (writer, _requests, reader) =
        serve::Tracks::new(TrackNamespace::from_utf8_path(&name)).produce();
    let media = moq_pub::Media::new(writer, None)?;

    tokio::select! {
        res = session.run() => res.context("session error")?,
        res = publisher.publish_namespace(reader) => res.context("PUBLISH_NAMESPACE error")?,
        res = feed_peer(media, hub, live) => res?,
    }
    Ok(())
}

// wait for the init segment to be populated in the shared state (hub)
async fn wait_for_init(hub: &Hub) -> Result<Bytes> {
    let mut rx = hub.init.subscribe();
    let init = rx
        .wait_for(|init| init.is_some())
        .await
        .context("video source stopped")?
        .clone();
    init.context("missing init segment")
}

/// Feed one subscriber's "Media".
/// Feeds init segment (with codec info, etc. to understand the coming data)
/// Then live fragments starting from a keyframe.
async fn feed_peer(
    mut media: moq_pub::Media,
    hub: Arc<Hub>,
    mut live: broadcast::Receiver<Fragment>,
) -> Result<()> {
    let mut init = wait_for_init(&hub).await?;
    media
        .parse(&mut init)
        .context("failed to publish the init segment")?;

    let mut started = false;
    loop {
        match live.recv().await {
            Ok(mut fragment) => {
                started |= fragment.keyframe;
                if started {
                    media
                        .parse(&mut fragment.data)
                        .context("failed to publish a fragment")?;
                }
            }
            Err(broadcast::error::RecvError::Lagged(missed)) => {
                anyhow::bail!("subscriber too slow: dropped after missing {missed} fragments")
            }
            Err(broadcast::error::RecvError::Closed) => anyhow::bail!("video source stopped"),
        }
    }
}

/// Turn the video file into fragmented MP4 with ffmpeg and hand it to the hub.
/// moq-pub expects a single H.264 video track in low-latency fMP4 (one fragment per
/// frame) and doesn't handle EOF yet, so we re-encode to that shape and loop the input.
async fn run_ffmpeg(file: &Path, hub: Arc<Hub>) -> Result<()> {
    hub.first_peer.notified().await;
    tracing::info!("starting ffmpeg");

    let mut child = Command::new("ffmpeg")
        .args([
            "-hide_banner", // no copyright/version
            "-loglevel",
            "error",
            "-re", // read input at native frame rate
            "-stream_loop",
            "-1",
            "-i", // input file
        ])
        .arg(file)
        .args([
            "-map",
            "0:v:0",
            "-map",
            "0:a:0?", // "?" = we can have an audio track, or not
            // Video track flags
            "-c:v",
            "libx264", // codec = H.264
            "-profile:v",
            "main",
            "-preset",
            "veryfast",
            "-tune",
            "zerolatency",
            "-pix_fmt",
            "yuv420p", // pixel format
            "-g",
            "48", // GOP (group of pictures) size. always begins with an I-frame (keyframe)
            "-keyint_min",
            "48", // minimum interval between I-frames
            "-sc_threshold",
            "0",
            // Audio track flags
            // the moq-pub crate supports only the AAC codec
            "-c:a",
            "aac", // codec
            "-b:a",
            "128k", // bitrate (128kbps)
            "-ar",
            "48000", // sampling frequency
            "-ac",
            "2", // number of audio channels (2 = stereo)
            "-f",
            "mp4",
            "-movflags",
            "empty_moov+separate_moof+omit_tfhd_offset",
            "-frag_duration",
            "1000",
            "-",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to start ffmpeg (is it installed and on PATH?)")?;

    let mut stdout = child.stdout.take().context("ffmpeg stdout unavailable")?;
    let mut buf = BytesMut::new();
    let mut init = BytesMut::new();
    let mut pending_moof: Option<(Bytes, bool)> = None;

    let mut video_track: Option<u32> = None;

    loop {
        // We read the raw output from ffmpeg stdout: it outputs raw boxes (binary)
        let n = stdout
            .read_buf(&mut buf)
            .await
            .context("failed to read from ffmpeg")?;
        if n == 0 {
            break;
        }

        // MP4 boxes are also called "atoms"
        while let Some(atom) = next_box(&mut buf)? {
            // The 4 bytes after the 4 "size" bytes represent the type of box (ftyp, moov, moof, mdat)
            let kind: [u8; 4] = atom[4..8].try_into()?;
            match &kind {
                b"ftyp" => init.extend_from_slice(&atom),
                b"moov" => {
                    init.extend_from_slice(&atom);
                    video_track = Some(find_video_track(&atom)?);
                    hub.init.send_replace(Some(init.split().freeze()));
                    tracing::info!("init segment ready");
                }
                b"moof" => {
                    let video = video_track.context("moof recieved before moov")?;
                    let keyframe = is_video_keyframe(&atom, video)?;
                    pending_moof = Some((atom, keyframe));
                }
                b"mdat" => {
                    if let Some((moof, keyframe)) = pending_moof.take() {
                        let mut data = BytesMut::with_capacity(moof.len() + atom.len());
                        data.extend_from_slice(&moof);
                        data.extend_from_slice(&atom);
                        // An error only means nobody is subscribed right now.
                        let _ = hub.live.send(Fragment {
                            data: data.freeze(),
                            keyframe,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    let status = child.wait().await?;
    anyhow::bail!("ffmpeg exited unexpectedly: {status}")
}

// Find the track id of the H.264 (avc1) track (there is one video and one audio track, so this is to know which is which)
fn find_video_track(moov_box: &[u8]) -> Result<u32> {
    let mut reader = Cursor::new(moov_box);
    let header = mp4::BoxHeader::read(&mut reader)?;
    let moov = mp4::MoovBox::read_box(&mut reader, header.size)?;
    moov.traks
        .iter()
        .find(|trak| trak.mdia.minf.stbl.stsd.avc1.is_some()) // is it AVC? (advanced video coding) => video track
        .map(|trak| trak.tkhd.track_id) // fetch its track id
        .context("ffmpeg output has no H.264 video track")
}

// MP4 files are structured as a sequence of "boxes".
// As the output from ffmpeg is raw bytes, this function cuts this stream into boxes.
fn next_box(buf: &mut BytesMut) -> Result<Option<Bytes>> {
    // The mp4 box header is 8 bytes long (size + type)
    if buf.len() < 8 {
        return Ok(None);
    }
    // First 4 bytes of the box represent the total size of the box
    // Size is encoded as a big endian integer
    let size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    anyhow::ensure!(size >= 8, "unsupported MP4 box size {size}");
    if buf.len() < size {
        // The buffer doesn't contain the whole box yet
        return Ok(None);
    }
    // We return the box as immutable bytes and chop it off "buf" so it only contains the next stuff.
    Ok(Some(buf.split_to(size).freeze()))
}

// In H.264 some frames can be decoded on their own (I-frames, or "keyframes")
// Some are dependent on other frames to be decoded (P/B-frames).
// The subscriber needs to join on a keyframe to be able to understand the stream
fn is_video_keyframe(moof_box: &[u8], video_track: u32) -> Result<bool> {
    let mut reader = Cursor::new(moof_box);
    let header = mp4::BoxHeader::read(&mut reader)?;
    let moof = mp4::MoofBox::read_box(&mut reader, header.size)?;

    // Each moof box can contain multiple tracks "traf" (for example one audio and one video)
    for traf in &moof.trafs {
        if traf.tfhd.track_id != video_track {
            continue;
        }
        let default_flags = traf.tfhd.default_sample_flags.unwrap_or_default();
        let Some(trun) = &traf.trun else {
            return Ok(false);
        };

        for i in 0..trun.sample_count {
            // Flags can be specified at either "trun" or "tfhd" level.
            let mut flags = match trun.sample_flags.get(i as usize) {
                Some(f) => *f,
                None => default_flags, // if there are none we fall back on tfhd flags
            };
            // if the "first_sample_flags" field is present it takes precedence over flags for the first sample
            if i == 0 {
                if let Some(first_flags) = trun.first_sample_flags {
                    flags = first_flags;
                }
            }

            // extract bits 24-25 = sample_depends_on
            let depends_on_none = (flags >> 24) & 0x3 == 0x2;
            // bit 16 = sample_is_non_sync_sample
            let non_sync = (flags >> 16) & 0x1 == 0x1;
            if depends_on_none && !non_sync {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Write a throwaway self-signed certificate + key (PEM) into "dir".
fn write_self_signed(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    let certified = rcgen::generate_simple_self_signed(names)
        .context("failed to generate self-signed certificate")?;
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, certified.cert.pem())?;
    std::fs::write(&key, certified.signing_key.serialize_pem())?;
    Ok((cert, key))
}

fn is_global_unicast(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xe000) == 0x2000
}

fn is_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn pick_ipv6(addrs: impl IntoIterator<Item = IpAddr>) -> Option<Ipv6Addr> {
    let mut ula = None;
    for addr in addrs {
        let IpAddr::V6(ip) = addr else {
            continue;
        };
        if is_global_unicast(ip) {
            return Some(ip);
        }
        if ula.is_none() && is_unique_local(ip) {
            ula = Some(ip);
        }
    }
    ula
}

/// Find a routable non-loopback IPv6 address for the join ticket.
///
/// Avoids `local_ip_address::local_ipv6()`, which fails on Linux when the default IPv6 route
/// has no `RTA_PREFSRC` because its `RTM_GETADDR` fallback checks `IFA_LOCAL` instead of `IFA_ADDRESS`.
fn detect_publisher_ipv6() -> Result<Ipv6Addr> {
    // UDP connect sends no packets; it asks the kernel for RFC 6724 source address selection.
    if let Ok(sock) = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) {
        let probe = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            80,
        );
        if sock.connect(probe).is_ok() {
            if let Ok(SocketAddr::V6(local)) = sock.local_addr() {
                let ip = *local.ip();
                if is_global_unicast(ip) || is_unique_local(ip) {
                    return Ok(ip);
                }
            }
        }
    }

    let ifas = list_afinet_netifas().context("failed to list network interfaces")?;
    pick_ipv6(ifas.into_iter().filter(|(name, _)| name != "lo").map(|(_, ip)| ip)).context(
        "failed to find a routable IPv6 address (global or ULA); loopback and link-local (fe80::) cannot be used in a ticket",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn pick_ipv6_prefers_global_and_ignores_loopback_and_link_local() {
        let addrs = [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            IpAddr::V6("fd12:3456:789a::1".parse().unwrap()),
            IpAddr::V6("2a01:cb00:1234::42".parse().unwrap()),
        ];
        assert_eq!(
            pick_ipv6(addrs),
            Some("2a01:cb00:1234::42".parse().unwrap())
        );

        let ula_only = [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("fd12:3456:789a::1".parse().unwrap()),
        ];
        assert_eq!(
            pick_ipv6(ula_only),
            Some("fd12:3456:789a::1".parse().unwrap())
        );

        let unusable = [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("::ffff:192.0.2.1".parse().unwrap()),
        ];
        assert_eq!(pick_ipv6(unusable), None);
    }

    #[tokio::test]
    async fn publish_and_subscribe_streams_fmp4_and_intercepts_punch() {
        let video = Path::new(env!("CARGO_MANIFEST_DIR")).join("vid/test.mp4");
        let pub_node_id = [42u8; 32];
        let mut publisher = Publisher::bind_with(
            &video,
            pub_node_id,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            None,
        )
        .await
        .unwrap();

        let decoded = crate::decode_ticket(publisher.ticket()).unwrap();
        assert_eq!(decoded.node_id, pub_node_id);
        assert_eq!(decoded.ip, IpAddr::V6(Ipv6Addr::LOCALHOST));

        let addr = publisher.server.local_addr().unwrap();

        // Fire a HALO_PUNCH UDP packet from a peer socket and verify ThiefSocket steals it
        // AND verify punch_peer sends a HALO_PUNCH back from the publisher's QUIC socket.
        let peer_sock = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        let peer_node_id = [7u8; 32];

        publisher.punch_peer(peer_addr).await.unwrap();
        let mut recv_buf = [0u8; 128];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), peer_sock.recv_from(&mut recv_buf))
            .await
            .expect("timed out waiting for outbound HALO_PUNCH")
            .unwrap();
        assert_eq!(from, addr);
        assert_eq!(
            crate::parse_punch(from, &recv_buf[..n]),
            Some(crate::PunchPacket {
                from: addr,
                node_id: Some(pub_node_id),
            })
        );

        peer_sock
            .send_to(&crate::encode_punch(&peer_node_id), addr)
            .await
            .unwrap();

        // Take a punch assertion channel by polling before moving publisher into run(),
        // or inspect after spawning — drive the QUIC endpoint by starting subscriber too.
        let (mut reader, writer) = tokio::io::duplex(64 * 1024);
        let sub_task = tokio::spawn(crate::subscribe(addr, writer, None));

        let stolen = tokio::time::timeout(
            Duration::from_secs(5),
            publisher.thief_mut().recv_punch(),
        )
        .await
        .expect("timed out waiting for stolen HALO_PUNCH")
        .expect("punch channel closed");
        assert_eq!(stolen.from, peer_addr);
        assert_eq!(stolen.node_id, Some(peer_node_id));

        let pub_task = tokio::spawn(publisher.run());

        let mut header = [0u8; 8];
        tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut header))
            .await
            .expect("timed out waiting for fMP4 stream")
            .expect("failed to read fMP4 header");
        assert_eq!(&header[4..8], b"ftyp");

        sub_task.abort();
        pub_task.abort();
    }
}
