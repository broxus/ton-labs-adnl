use std::cmp::Ordering;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{self, AtomicI32, AtomicU32, AtomicU64};
use std::sync::Arc;

use aes::cipher::StreamCipher;
use dashmap::DashMap;
use sha2::Digest;
use socket2::{Domain, Socket};
use tokio::sync::mpsc;
use ton_api::ton;
use ton_api::ton::pub_::publickey::Aes as AesKey;
use ton_types::{fail, Result};

use crate::common::{hash, now, AdnlCryptoUtils, AdnlPeers, KeyId, KeyOption, Query, Subscriber};
use std::time::{Duration, Instant};

pub struct AdnlNode {
    config: AdnlNodeConfig,
    channels_receive: Arc<ChannelsReceive>,
    channels_send: Arc<ChannelsSend>,
    channels_wait: Arc<ChannelsSend>,
    peers: DashMap<Arc<KeyId>, Arc<Peers>>,
    start_time: i32,
    stop: Arc<AtomicU32>,
}

impl AdnlNode {
    pub async fn with_config(mut config: AdnlNodeConfig) -> Result<Arc<Self>> {
        if config.keys.is_empty() {
            fail!("No keys configured for node");
        }

        let peers = DashMap::new();
        for key in config.keys.iter() {
            peers.insert(key.value().id().clone(), Arc::new(DashMap::new()));
        }

        if config.ip_address.ip() == 0 {
            let ip = external_ip::ConsensusBuilder::new()
                .add_sources(external_ip::get_http_sources::<external_ip::Sources>())
                .build()
                .get_consensus()
                .await;
            if let Some(IpAddr::V4(ip)) = ip {
                config.ip_address.set_ip(u32::from_be_bytes(ip.octets()))
            } else {
                fail!("Cannot obtain external IPv4 address")
            }
        }

        let (queue_sender, queue_reader) = mpsc::unbounded_channel();
        let (queue_local_sender, queue_local_reader) = mpsc::unbounded_channel();

        let result = Self {
            config,
            channels_receive: Arc::new(Default::default()),
            channels_send: Arc::new(Default::default()),
            channels_wait: Arc::new(Default::default()),
            peers,
            start_time: now(),
            stop: Arc::new(AtomicU32::new(0)),
        };

        Ok(Arc::new(result))
    }

    pub async fn start(node: &Arc<Self>) -> Result<()> {
        let socket_receive = Socket::new(Domain::IPV4, socket2::Type::DGRAM, None)?;
        socket_receive.set_recv_buffer_size(1 << 20)?;
        socket_receive.bind(
            &SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                node.config.ip_address.port(),
            )
            .into(),
        )?;

        let socket_send = socket_receive.try_clone()?;

        let start = Arc::new(Instant::now());

        let node_stop = node.clone();
        tokio::spawn(async move {
            // TODO: await stop
        });
    }

    pub async fn stop(&self) {
        // TODO
    }

    pub fn add_key(&self, key: KeyOption, tag: usize) -> Result<Arc<KeyId>> {
        let result = self.config.add_key(key, tag)?;

        Ok(result)
    }

    async fn peers(&self, src: &Arc<KeyId>) -> Result<Arc<Peers>> {
        if let Some(peers) = self.peers.get(src) {
            Ok(peers.value().clone())
        } else {
            fail!("Cannot get peers list for unknown local key {}", src)
        }
    }

    async fn process_query(
        subscribers: &[Arc<dyn Subscriber>],
        query: &AdnlQueryMessage,
        peers: &AdnlPeers,
    ) -> Result<Option<AdnlMessage>> {
    }
}

pub struct AdnlNodeConfig {
    ip_address: IpAddress,
    keys: DashMap<Arc<KeyId>, Arc<KeyOption>>,
    tags: DashMap<usize, Arc<KeyId>>,
    throughput: Option<u32>,
}

impl AdnlNodeConfig {
    pub fn ip_address(&self) -> &IpAddress {
        &self.ip_address
    }

    pub fn key_by_id(&self, id: &Arc<KeyId>) -> Result<Arc<KeyOption>> {
        if let Some(key) = self.keys.get(id) {
            Ok(key.clone())
        } else {
            fail!("Bad key id {}", id)
        }
    }

    pub fn key_by_tag(&self, tag: usize) -> Result<Arc<KeyOption>> {
        if let Some(id) = self.tags.get(&tag) {
            self.key_by_id(id.value())
        } else {
            fail!("Bad key tag {}", tag)
        }
    }

    pub fn set_port(&mut self, port: u16) {
        self.ip_address.set_port(port)
    }

    pub fn set_throughput(&mut self, throughput: Option<u32>) {
        self.throughput = if let Some(0) = &throughput {
            None
        } else {
            throughput
        }
    }

    pub fn add_key(&self, key: KeyOption, tag: usize) -> Result<Arc<KeyId>> {
        use dashmap::mapref::entry::Entry;

        let mut result = key.id().clone();

        let added = match self.tags.entry(tag) {
            Entry::Vacant(entry) => {
                entry.insert(key.id().clone());
                true
            }
            Entry::Occupied(entry) => {
                if entry.get() != key.id() {
                    fail!("Duplicated key tag {} in node", tag);
                }
                false
            }
        };

        if added {
            let key = Arc::new(key);
            match self.keys.entry(result.clone()) {
                Entry::Vacant(entry) => entry.insert(key),
                Entry::Occupied(_) => fail!("Duplicated key {} in node", result),
            }
        }

        Ok(result)
    }

    fn delete_key(&self, key: &Arc<KeyId>, tag: usize) -> Result<bool> {
        let removed_key = self.keys.remove(key);
        if let Some((_, ref removed)) = self.tags.remove(&tag) {
            if removed != key {
                fail!("Expected {} key with tag {} but got {}", key, tag, removed);
            }
        }
        Ok(removed_key.is_some())
    }
}

struct AdnlNodeAddress {
    channel_key: Arc<KeyOption>,
}

struct AdnlChannel {
    local_key: Arc<KeyId>,
    other_key: Arc<KeyId>,
    receive_channel: ChannelSide,
    send_channel: ChannelSide,
}

impl AdnlChannel {
    fn with_keys(
        local_key: &Arc<KeyId>,
        channel_private_key: &Arc<KeyOption>,
        other_key: &Arc<KeyId>,
        channel_public_key: &[u8; 32],
    ) -> Result<Self> {
        let forward_secret =
            AdnlCryptoUtils::calc_shared_secret(channel_private_key.pvt_key()?, channel_public_key);

        let cmp = local_key.cmp(other_key);

        let (forward_secret, reversed_secret) = if Ordering::Equal == cmp {
            (forward_secret, forward_secret)
        } else {
            let mut reversed_secret = forward_secret.clone();
            reversed_secret.reverse();
            if cmp == Ordering::Less {
                (forward_secret, reversed_secret)
            } else {
                (reversed_secret, forward_secret)
            }
        };

        Ok(Self {
            local_key: local_key.clone(),
            other_key: other_key.clone(),
            receive_channel: ChannelSide::from_secret(forward_secret)?,
            send_channel: ChannelSide::from_secret(reversed_secret)?,
        })
    }

    fn decrypt_inplace(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if buffer.len() < 64 {
            fail!("Channel message is too short: {}", buf.len())
        }
        Self::process_data_inplace(buffer, &self.receive_channel.secret);
        if sha2::Sha256::digest(&buffer[64..]).as_slice() != &buffer[32..64] {
            fail!("Bad channel message checksum");
        }
        buffer.drain(0..64);
        Ok(())
    }

    fn encrypt_inplace(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let checksum: [u8; 32] = {
            let checksum = sha2::Sha256::digest(buffer.as_slice());
            checksum.as_slice().try_into().unwrap()
        };

        let len = buffer.len();
        buffer.resize(len + 64, 0);
        buffer.copy_within(..len, 64);
        buffer[..32].copy_from_slice(&self.send_channel.id);
        buffer[32..64].copy_from_slice(&checksum);
        Self::process_data_inplace(buffer, &self.send_channel.secret);
        Ok(())
    }

    fn process_data_inplace(buffer: &mut Vec<u8>, secret: &[u8; 32]) {
        let digest = &buffer[32..64];
        let mut key = crate::from_slice!(secret, 0, 16, digest, 16, 16);
        let mut ctr = crate::from_slice!(digest, 0, 4, secret, 20, 12);
        AdnlCryptoUtils::build_cipher_secure(&mut key[..], &mut ctr[..])
            .apply_keystream(&mut buffer[64..])
    }
}

struct ChannelSide {
    id: ChannelId,
    secret: [u8; 32],
}

impl ChannelSide {
    fn from_secret(secret: [u8; 32]) -> Result<Self> {
        Ok(Self {
            id: calc_channel_id(&secret)?,
            secret,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Hash)]
pub struct IpAddress(u64);

impl IpAddress {
    pub fn from_string(str: &str) -> Result<Self> {
        let addr = str.parse::<SocketAddr>()?;
        if let IpAddr::V4(ip) = addr.ip() {
            Ok(Self::from_ip_and_port(
                u32::from_be_bytes(ip.octets()),
                addr.port(),
            ))
        } else {
            fail!("IPv6 addressed are not supported")
        }
    }

    pub fn into_udp(self) -> ton::adnl::address::address::Udp {
        ton::adnl::address::address::Udp {
            ip: self.ip() as i32,
            port: self.port() as i32,
        }
    }

    fn from_ip_and_port(ip: u32, port: u16) -> Self {
        Self(((ip as u64) << 16) | port as u64)
    }

    fn ip(&self) -> u32 {
        (self.0 >> 16) as u32
    }

    fn port(&self) -> u16 {
        self as u16
    }

    fn set_ip(&mut self, new_ip: u32) {
        self.0 = ((new_ip as u64) << 16) | (self.0 & 0xffff)
    }

    fn set_port(&mut self, new_port: u16) {
        self.0 = (self.0 & 0xffffffff0000u64) | new_port as u64
    }
}

impl std::fmt::Debug for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}:{}",
            self.0 >> 40 as u8,
            self.0 >> 32 as u8,
            self.0 >> 24 as u8,
            self.0 >> 16 as u8,
            self.0 as u16
        )
    }
}

type ChannelId = [u8; 32];

fn calc_channel_id(secret: &[u8; 32]) -> Result<ChannelId> {
    hash(AesKey {
        key: ton::int256(secret.clone()),
    })
}

struct Peer {
    address: AdnlNodeAddress,
    receiver_state: PeerState,
    sender_state: PeerState,
}

pub struct PeerHistory {
    index: AtomicU64,
    seqno: AtomicU64,
}

impl PeerHistory {
    fn new() -> Self {
        Self {
            index: AtomicU64::new(0),
            seqno: AtomicU64::new(0),
        }
    }
}

struct PeerState {
    history: PeerHistory,
    reinit_date: AtomicI32,
}

impl PeerState {
    fn for_receive_with_reinit_date(reinit_date: i32) -> Self {
        Self {
            history: PeerHistory::new(),
            reinit_date: AtomicI32::new(reinit_date),
        }
    }

    fn for_send() -> Self {
        Self {
            history: PeerHistory::new(),
            reinit_date: AtomicI32::new(0),
        }
    }

    fn bump_seqno(&self) -> u64 {
        self.history.seqno.fetch_add(1, atomic::Ordering::Relaxed) + 1
    }

    fn seqno(&self) -> u64 {
        self.history.seqno.load(atomic::Ordering::Acquire)
    }

    fn reinit_date(&self) -> i32 {
        self.reinit_date.load(atomic::Ordering::Acquire)
    }

    fn reset_reinit_date(&self, reinit_date: i32) {
        self.reinit_date
            .store(reinit_date, atomic::Ordering::Relaxed)
    }
}

type ChannelsReceive = DashMap<ChannelId, Arc<AdnlChannel>>;
type ChannelsSend = DashMap<Arc<KeyId>, Arc<AdnlChannel>>;
type Peers = DashMap<Arc<KeyId>, Peer>;
type TransferId = [u8; 32];
