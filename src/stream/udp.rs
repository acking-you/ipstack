use crate::{
    IpStackError, PacketReceiver, PacketSender, TTL,
    packet::{IpHeader, NetworkPacket, TransportHeader},
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, UdpHeader};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{future::Future, net::SocketAddr, pin::Pin, time::Duration};
static NEXT_FRAGMENT_ID: AtomicU32 = AtomicU32::new(1);
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    time::Sleep,
};

/// A UDP stream in the IP stack.
///
/// This type represents a UDP connection and implements `AsyncRead` and `AsyncWrite`
/// for bidirectional data transfer. UDP streams have a configurable timeout and
/// automatically handle packet fragmentation based on MTU.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
/// if let IpStackStream::Udp(mut udp_stream) = ip_stack.accept().await? {
///     println!("New UDP stream from {}", udp_stream.peer_addr());
///     
///     // Read data
///     let mut buffer = [0u8; 1024];
///     let n = udp_stream.read(&mut buffer).await?;
///     
///     // Write data
///     udp_stream.write_all(b"Response").await?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct IpStackUdpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: PacketReceiver,
    up_pkt_sender: PacketSender,
    first_payload: Option<Vec<u8>>,
    timeout: Pin<Box<Sleep>>,
    timeout_interval: Duration,
    mtu: u16,
    destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
}

impl IpStackUdpStream {
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: Vec<u8>,
        up_pkt_sender: PacketSender,
        mtu: u16,
        timeout_interval: Duration,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
    ) -> Self {
        let (stream_sender, stream_receiver) = mpsc::unbounded_channel::<NetworkPacket>();
        let deadline = tokio::time::Instant::now() + timeout_interval;
        IpStackUdpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver,
            up_pkt_sender,
            first_payload: Some(payload),
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            timeout_interval,
            mtu,
            destroy_messenger,
        }
    }

    pub(crate) fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    fn create_rev_packet(&self, ttl: u8, payload: Vec<u8>) -> std::io::Result<NetworkPacket> {
        const UHS: usize = 8; // udp header size is 8
        match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::UDP, dst.octets(), src.octets()).map_err(IpStackError::from)?;
                ip_h.set_payload_len(payload.len() + UHS).map_err(IpStackError::from)?;
                let udp_header = UdpHeader::with_ipv4_checksum(self.dst_addr.port(), self.src_addr.port(), &ip_h, &payload)
                    .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv4(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload: Some(payload),
                })
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: IpNumber::UDP,
                    hop_limit: ttl,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                ip_h.payload_length =
                    u16::try_from(payload.len() + UHS).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
                let udp_header = UdpHeader::with_ipv6_checksum(self.dst_addr.port(), self.src_addr.port(), &ip_h, &payload)
                    .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv6(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload: Some(payload),
                })
            }
            _ => unreachable!(),
        }
    }

    /// Returns the local socket address of the UDP stream.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackUdpStream;
    /// # fn example(udp_stream: &IpStackUdpStream) {
    /// let local_addr = udp_stream.local_addr();
    /// println!("Local address: {}", local_addr);
    /// # }
    /// ```
    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Returns the remote socket address of the UDP stream.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use ipstack::IpStackUdpStream;
    /// # fn example(udp_stream: &IpStackUdpStream) {
    /// let peer_addr = udp_stream.peer_addr();
    /// println!("Peer address: {}", peer_addr);
    /// # }
    /// ```
    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    /// Receive one datagram, including an empty one. `None` means the stream
    /// ended; `Some(0)` is a valid empty UDP payload, never a TCP-style EOF.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> std::io::Result<Option<usize>> {
        std::future::poll_fn(|cx| {
            let mut buf = tokio::io::ReadBuf::new(buffer);
            self.poll_datagram(cx, &mut buf).map_ok(|item| item.map(|()| buf.filled().len()))
        })
        .await
    }

    /// Send exactly one UDP datagram. Oversized packets are IP fragments of
    /// that same datagram, with one UDP header and checksum for the whole body.
    pub fn send(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let packet = self.create_rev_packet(TTL, payload.to_vec())?;
        let header_len = match &packet.ip {
            IpHeader::Ipv4(h) => h.header_len(),
            IpHeader::Ipv6(h) => h.header_len(),
        };
        if header_len + 8 + payload.len() <= usize::from(self.mtu) {
            self.up_pkt_sender.send(packet).map_err(|_| std::io::ErrorKind::BrokenPipe)?;
        } else {
            let extension_len = if matches!(packet.ip, IpHeader::Ipv6(_)) { 8 } else { 0 };
            let chunk_size = usize::from(self.mtu).saturating_sub(header_len + extension_len) / 8 * 8;
            if chunk_size == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "MTU cannot fit an IP fragment",
                ));
            }
            let bytes = packet.to_bytes()?;
            let datagram = &bytes[header_len..];
            let id = NEXT_FRAGMENT_ID.fetch_add(1, Ordering::Relaxed);
            for (index, chunk) in datagram.chunks(chunk_size).enumerate() {
                let offset = (index * chunk_size / 8) as u16;
                let more = (index + 1) * chunk_size < datagram.len();
                let (ip, payload) = match &packet.ip {
                    IpHeader::Ipv4(original) => {
                        let mut ip = original.clone();
                        ip.identification = id as u16;
                        ip.dont_fragment = false;
                        ip.more_fragments = more;
                        ip.fragment_offset = etherparse::IpFragOffset::try_new(offset).map_err(std::io::Error::other)?;
                        ip.set_payload_len(chunk.len()).map_err(std::io::Error::other)?;
                        (IpHeader::Ipv4(ip), chunk.to_vec())
                    }
                    IpHeader::Ipv6(original) => {
                        let mut ip = original.clone();
                        ip.next_header = IpNumber::IPV6_FRAGMENTATION_HEADER;
                        ip.payload_length = (8 + chunk.len()) as u16;
                        let fragment = etherparse::Ipv6FragmentHeader::new(
                            IpNumber::UDP,
                            etherparse::IpFragOffset::try_new(offset).map_err(std::io::Error::other)?,
                            more,
                            id,
                        );
                        let mut payload = fragment.to_bytes().to_vec();
                        payload.extend_from_slice(chunk);
                        (IpHeader::Ipv6(ip), payload)
                    }
                };
                self.up_pkt_sender
                    .send(NetworkPacket {
                        ip,
                        transport: TransportHeader::Unknown,
                        payload: Some(payload),
                    })
                    .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
            }
        }
        self.reset_timeout();
        Ok(())
    }

    fn reset_timeout(&mut self) {
        let deadline = tokio::time::Instant::now() + self.timeout_interval;
        self.timeout.as_mut().reset(deadline);
    }
}

impl IpStackUdpStream {
    fn poll_datagram(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<Option<()>>> {
        if let Some(p) = self.first_payload.take() {
            // Clamp to `buf.remaining()`: an oversized datagram would otherwise
            // panic `put_slice` (hit under `copy_bidirectional` write
            // backpressure). Unlike the TCP path the remainder is DROPPED, not buffered matches `recvfrom` without MSG_WAITALL.
            let n = p.len().min(buf.remaining());
            buf.put_slice(&p[..n]);
            self.reset_timeout();
            return std::task::Poll::Ready(Ok(Some(())));
        }
        if matches!(self.timeout.as_mut().poll(cx), std::task::Poll::Ready(_)) {
            return std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        }

        match self.stream_receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(p)) => {
                self.reset_timeout();
                if let Some(payload) = p.payload {
                    // Clamp like the first_payload branch above (drop the tail).
                    let n = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..n]);
                }
                std::task::Poll::Ready(Ok(Some(())))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(None)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncRead for IpStackUdpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_datagram(cx, buf).map_ok(|_| ())
    }
}

impl AsyncWrite for IpStackUdpStream {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        self.send(buf)?;
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for IpStackUdpStream {
    fn drop(&mut self) {
        if let Some(messenger) = self.destroy_messenger.take() {
            let _ = messenger.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn udp_write_preserves_a_datagram_larger_than_mtu() {
        use tokio::io::AsyncWriteExt;
        for (src, dst, header_size) in [("127.0.0.1:1234", "127.0.0.1:53", 20), ("[::1]:1234", "[::1]:53", 40)] {
            let (sender, mut packets) = mpsc::unbounded_channel();
            let mut stream = IpStackUdpStream::new(
                src.parse().unwrap(),
                dst.parse().unwrap(),
                vec![],
                sender,
                1500,
                Duration::from_secs(30),
                None,
            );
            let payload = (0..4000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            stream.write_all(&payload).await.unwrap();
            let mut datagram = Vec::new();
            while let Ok(packet) = packets.try_recv() {
                let wire = packet.to_bytes().unwrap();
                assert!(wire.len() <= 1500);
                let offset = if header_size == 20 {
                    let offset = u16::from_be_bytes([wire[6], wire[7]]) & 0x1fff;
                    assert_eq!(usize::from(offset) * 8, datagram.len(), "fragments must share one UDP datagram");
                    header_size
                } else {
                    assert_eq!(wire[6], 44, "IPv6 fragment extension required");
                    let offset = u16::from_be_bytes([wire[42], wire[43]]) & 0xfff8;
                    assert_eq!(usize::from(offset), datagram.len());
                    header_size + 8
                };
                datagram.extend_from_slice(&wire[offset..]);
            }
            assert_eq!(u16::from_be_bytes([datagram[4], datagram[5]]) as usize, payload.len() + 8);
            assert_eq!(&datagram[8..], &payload);
            // Empty UDP is data, not stream EOF, in both directions.
            let mut input = [0; 1];
            assert_eq!(stream.recv(&mut input).await.unwrap(), Some(0));
            stream.send(&[]).unwrap();
            let empty = packets.try_recv().unwrap().to_bytes().unwrap();
            assert_eq!(empty.len(), header_size + 8);
            assert_eq!(&empty[header_size + 4..header_size + 6], &8u16.to_be_bytes());
            assert!(stream.send(&vec![0; 65536]).is_err());
            assert!(packets.try_recv().is_err());
        }
    }

    fn stream(first_payload: Vec<u8>) -> IpStackUdpStream {
        let (up_tx, _up_rx) = mpsc::unbounded_channel();
        IpStackUdpStream::new(
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            first_payload,
            up_tx,
            1500,
            Duration::from_secs(30),
            None,
        )
    }

    // A datagram larger than the caller's buffer used to panic `put_slice`; it
    // must now truncate to the buffer instead. Covers both branches of poll_read.

    #[tokio::test]
    async fn poll_read_truncates_oversized_first_payload() {
        let mut s = stream(vec![7u8; 1250]);
        let mut small = [0u8; 502];
        assert_eq!(s.read(&mut small).await.unwrap(), 502);
        assert!(small.iter().all(|&b| b == 7));
    }

    #[tokio::test]
    async fn poll_read_truncates_oversized_relayed_datagram() {
        let mut s = stream(Vec::new());
        s.first_payload = None; // skip to the stream_receiver branch
        let pkt = s.create_rev_packet(64, vec![9u8; 1250]).unwrap();
        s.stream_sender().send(pkt).unwrap();
        let mut small = [0u8; 502];
        assert_eq!(s.read(&mut small).await.unwrap(), 502);
    }
}
