use std::cmp::Ordering;
use std::convert::TryInto;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{self, AtomicI32, AtomicU32, AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aes::cipher::StreamCipher;
use dashmap::{DashMap, DashSet};
use sha2::Digest;
use socket2::{Domain, Socket};
use tokio::sync::mpsc;
use ton_api::ton::adnl::addresslist::AddressList;
use ton_api::ton::adnl::id::short::Short as AdnlIdShort;
use ton_api::ton::adnl::message::message::Answer as AdnlAnswerMessage;
use ton_api::ton::adnl::message::message::ConfirmChannel as ConfirmChannelMessage;
use ton_api::ton::adnl::message::message::CreateChannel as CreateChannelMessage;
use ton_api::ton::adnl::message::message::Custom as AdnlCustomMessage;
use ton_api::ton::adnl::message::message::Part as AdnlPartMessage;
use ton_api::ton::adnl::message::message::Query as AdnlQueryMessage;
use ton_api::ton::adnl::packetcontents::PacketContents;
use ton_api::ton::adnl::pong::Pong as AdnlPong;
use ton_api::ton::adnl::Address;
use ton_api::ton::adnl::Message as AdnlMessage;
use ton_api::ton::adnl::PacketContents as AdnlPacketContents;
use ton_api::ton::pub_::publickey::Aes as AesKey;
use ton_api::ton::rpc::adnl::Ping as AdnlPing;
use ton_api::ton::TLObject;
use ton_api::{ton, IntoBoxed};
use ton_types::{fail, Result};

use crate::common::*;

pub struct AdnlNode {
    config: AdnlNodeConfig,
    channels_receive: Arc<ChannelsReceive>,
    channels_send: Arc<ChannelsSend>,
    channels_wait: Arc<ChannelsSend>,
    peers: DashMap<Arc<KeyId>, Arc<Peers>>,
    queries: Arc<QueryCache>,
    queue_sender: mpsc::UnboundedSender<Job>,
    queue_reader: ReceiverContainer<Job>,
    queue_local_sender: mpsc::UnboundedSender<(AdnlMessage, Arc<KeyId>)>,
    queue_local_reader: ReceiverContainer<(AdnlMessage, Arc<KeyId>)>,
    start_time: i32,
    stop: Arc<AtomicU32>,
    transfers: Arc<DashMap<TransferId, Arc<Transfer>>>,
}

type ReceiverContainer<T> = Mutex<Option<mpsc::UnboundedReceiver<T>>>;

impl AdnlNode {
    const CLOCK_TOLERANCE: i32 = 60; // Seconds

    const TIMEOUT_ADDRESS: i32 = 1000; // Seconds
    const TIMEOUT_CHANNEL_RESET: u32 = 30; // Seconds
    const TIMEOUT_QUERY_MAX: u64 = 5000; // Milliseconds
    const TIMEOUT_QUERY_MIN: u64 = 500; // Milliseconds
    const TIMEOUT_TRANSFER: u64 = 3; // Seconds
    const TIMEOUT_QUERY_STOP: u64 = 1; // Milliseconds
    const TIMEOUT_SHUTDOWN: u64 = 2000; // Milliseconds

    const MAX_ADNL_MESSAGE_SIZE: usize = 1024;
    const MAX_MESSAGES_IN_PROGRESS: u32 = 512;
    const SIZE_BUFFER: usize = 2048;

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
        let (queue_local_sender, queue_local_reader) = tokio::sync::mpsc::unbounded_channel();

        let result = Self {
            config,
            channels_receive: Arc::new(Default::default()),
            channels_send: Arc::new(Default::default()),
            channels_wait: Arc::new(Default::default()),
            peers,
            queries: Arc::new(Default::default()),
            queue_sender,
            queue_reader: Mutex::new(Some(queue_reader)),
            queue_local_sender,
            queue_local_reader: Mutex::new(Some(queue_local_reader)),
            start_time: now(),
            stop: Arc::new(AtomicU32::new(0)),
            transfers: Arc::new(Default::default()),
        };

        Ok(Arc::new(result))
    }

    pub async fn start(node: &Arc<Self>, mut subscribers: Vec<Arc<dyn Subscriber>>) -> Result<()> {
        let mut queue_reader = node
            .queue_reader
            .lock()
            .ok()
            .and_then(|mut rx| rx.take())
            .ok_or_else(|| ton_types::error!("ADNL node already started"))?;
        let mut queue_local_reader = node
            .queue_local_reader
            .lock()
            .ok()
            .and_then(|mut rx| rx.take())
            .ok_or_else(|| ton_types::error!("ADNL node already started"))?;

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

        subscribers.push(Arc::new(AdnlPingSubscriber));

        let start = Arc::new(Instant::now());
        let subscribers = Arc::new(subscribers);

        for subscriber in subscribers.iter() {
            let node = node.clone();
            let start = start.clone();
            let subscriber = subscriber.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
                    if node.stop.load(atomic::Ordering::Acquire) > 0 {
                        break;
                    }
                    subscriber.poll(&start).await;
                }
            });
        }

        tokio::spawn({
            let node = node.clone();

            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
                    if node.stop.load(atomic::Ordering::Acquire) > 0 {
                        if let Err(e) = node.queue_sender.send(Job::Stop) {
                            log::warn!("Cannot close node socket: {}", e);
                        }
                        let stop = (AdnlMessage::Adnl_Message_Nop, KeyId::from_data([0u8; 32]));
                        if let Err(e) = node.queue_local_sender.send(stop) {
                            log::warn!("Cannot close node loopback: {}", e);
                        }
                        break;
                    }
                }
                node.stop.fetch_add(1, atomic::Ordering::Release);
                log::warn!("Node stopping watchdog exited");
            }
        });

        let (queue_receive_sender, mut queue_receive_reader) = mpsc::unbounded_channel();
        let queue_receive_sent = Arc::new(AtomicU64::new(0));
        let queue_receive_read = Arc::new(AtomicU64::new(0));

        tokio::spawn({
            let node = node.clone();

            async move {
                let mut buffer_src = None;
                loop {
                    if node.stop.load(atomic::Ordering::Acquire) > 0 {
                        break;
                    }
                    let buffer = buffer_src.get_or_insert_with(|| {
                        vec![MaybeUninit::<u8>::uninit(); Self::SIZE_BUFFER]
                    });
                    let len = match socket_receive.recv(&mut buffer[..]) {
                        Ok(len) if len == 0 => continue,
                        Ok(len) => len,
                        Err(e) => {
                            match e.kind() {
                                std::io::ErrorKind::WouldBlock => std::thread::yield_now(),
                                _ => log::warn!("ERROR <-- {}", e),
                            };
                            continue;
                        }
                    };

                    let mut buffer = match buffer_src.take() {
                        Some(buffer) => buffer,
                        None => continue,
                    };

                    buffer.truncate(len);
                    if let Err(e) = queue_receive_sender.send(buffer) {
                        log::error!("ERROR in recv queue {}", e);
                    } else {
                        queue_receive_sent.fetch_add(1, atomic::Ordering::Release);
                    }
                }
                queue_receive_sent.fetch_add(1, atomic::Ordering::Release);
            }
        });

        tokio::spawn({
            let node = node.clone();
            let subscribers = subscribers.clone();

            async move {
                let proc_load = Arc::new(AtomicU32::new(0));
                loop {
                    if queue_receive_read.load(atomic::Ordering::Acquire) == 0 {
                        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
                        continue;
                    }

                    let current_load = proc_load.load(atomic::Ordering::Acquire);
                    if current_load > Self::MAX_MESSAGES_IN_PROGRESS {
                        tokio::task::yield_now().await;
                        continue;
                    }

                    let mut buffer = match queue_receive_reader.recv().await {
                        Some(buffer) => buffer,
                        None => break,
                    };

                    queue_receive_read.fetch_sub(1, atomic::Ordering::Release);
                    let node = node.clone();
                    let proc_load = proc_load.clone();
                    let subscribers = subscribers.clone();
                    proc_load.fetch_add(1, atomic::Ordering::Release);
                    tokio::spawn({
                        async move {
                            // SAFETY: buffer is guaranteed to be initialized
                            let buffer_view =
                                unsafe { PacketView::from_uninit(buffer.as_mut_slice()) };

                            if let Err(e) = node.receive(buffer_view, &subscribers).await {
                                log::warn!("ERROR <-- {}", e)
                            }
                            proc_load.fetch_sub(1, atomic::Ordering::Release);
                        }
                    });
                }
                node.stop.fetch_add(1, atomic::Ordering::Release);
                log::warn!("Node socket receiver exited");
            }
        });

        tokio::spawn({
            use std::collections::VecDeque;

            let node = node.clone();

            async move {
                const PERIOD_NANOS: u64 = 1000000;
                let start = Instant::now();
                let mut history = None;
                while let Some(job) = queue_reader.recv().await {
                    let (job, stop) = match job {
                        Job::Send(job) => (job, false),
                        Job::Stop => (
                            SendJob {
                                destination: 0x7F0000010000u64
                                    | node.config.ip_address.port() as u64,
                                data: Vec::new(),
                            },
                            true,
                        ),
                    };

                    if let Some(throughput) = node.config.throughput {
                        let history = history
                            .get_or_insert_with(|| VecDeque::with_capacity(throughput as usize));
                        if history.len() >= throughput as usize {
                            if let Some(time) = history.pop_front() {
                                while start.elapsed().as_nanos() - time < (PERIOD_NANOS as u128) {
                                    tokio::task::yield_now().await;
                                }
                            }
                        }
                        history.push_back(start.elapsed().as_nanos());
                    }

                    let addr = SocketAddrV4::new(
                        Ipv4Addr::from(((job.destination >> 16) as u32).to_be_bytes()),
                        job.destination as u16,
                    )
                    .into();

                    loop {
                        match socket_send.send_to(job.data.as_slice(), &addr) {
                            Ok(size) => {
                                if size != job.data.len() {
                                    log::error!(
                                        "Incomplete send: {} bytes of {}",
                                        size,
                                        job.data.len()
                                    )
                                }
                            }
                            Err(e) => match e.kind() {
                                std::io::ErrorKind::WouldBlock => {
                                    tokio::task::yield_now().await;
                                    continue;
                                }
                                _ => log::error!("ERROR --> {}", e),
                            },
                        }
                        break;
                    }

                    if node.stop.load(atomic::Ordering::Acquire) > 0 && stop {
                        break;
                    }
                }
                node.stop.fetch_add(1, atomic::Ordering::Release);
                log::warn!("Node socket sender exited");
            }
        });

        tokio::spawn({
            let node = node.clone();
            let subscribers = subscribers.clone();

            async move {
                while let Some((message, src)) = queue_local_reader.recv().await {
                    if node.stop.load(atomic::Ordering::Acquire) > 0 {
                        break;
                    }
                    let query = match message {
                        AdnlMessage::Adnl_Message_Query(query) => query,
                        x => {
                            log::warn!("Unsupported local ADNL message {:?}", x);
                            continue;
                        }
                    };

                    let node = node.clone();
                    let peers = AdnlPeers::with_keys(src.clone(), src.clone());
                    let subscribers = subscribers.clone();
                    tokio::spawn(async move {
                        let answer = match Self::process_query(&subscribers, &query, &peers).await {
                            Ok(Some(AdnlMessage::Adnl_Message_Answer(answer))) => answer,
                            Ok(Some(x)) => {
                                log::warn!("Unexpected reply {:?}", x);
                                return;
                            }
                            Err(e) => {
                                log::warn!("ERROR --> {}", e);
                                return;
                            }
                            _ => return,
                        };
                        if let Err(e) = node.process_answer(&answer, &src).await {
                            log::warn!("ERROR --> {}", e);
                        }
                    });
                }
                node.stop.fetch_add(1, atomic::Ordering::Release);
                log::warn!("Node loopback exited");
            }
        });

        Ok(())
    }

    pub async fn stop(&self) {
        log::warn!("Stopping ADNL node");
        self.stop.fetch_add(1, atomic::Ordering::Release);
        loop {
            tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_QUERY_STOP)).await;
            if self.stop.load(atomic::Ordering::Acquire) >= 5 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_SHUTDOWN)).await;
        log::warn!("ADNL node stopped");
    }

    pub fn add_key(&self, key: KeyOption, tag: usize) -> Result<Arc<KeyId>> {
        use dashmap::mapref::entry::Entry;

        let result = self.config.add_key(key, tag)?;
        if let Entry::Vacant(entry) = self.peers.entry(result.clone()) {
            entry.insert(Arc::new(Default::default()));
        }

        Ok(result)
    }

    pub fn delete_key(&self, key: &Arc<KeyId>, tag: usize) -> Result<bool> {
        self.peers.remove(key);
        self.config.delete_key(key, tag)
    }

    pub fn key_by_id(&self, id: &Arc<KeyId>) -> Result<Arc<KeyOption>> {
        self.config.key_by_id(id)
    }

    pub fn key_by_tag(&self, tag: usize) -> Result<Arc<KeyOption>> {
        self.config.key_by_tag(tag)
    }

    pub fn ip_address(&self) -> IpAddress {
        self.config.ip_address()
    }

    pub fn build_address_list(&self, expire_at: Option<i32>) -> Result<AddressList> {
        let version = now();
        Ok(AddressList {
            addrs: vec![self.config.ip_address.into_udp().into_boxed()].into(),
            version,
            reinit_date: self.start_time,
            priority: 0,
            expire_at: expire_at.unwrap_or_default(),
        })
    }

    pub fn calc_timeout(roundtrip: Option<u64>) -> u64 {
        let timeout = roundtrip.unwrap_or(Self::TIMEOUT_QUERY_MAX);
        if timeout < Self::TIMEOUT_QUERY_MIN {
            Self::TIMEOUT_QUERY_MIN
        } else {
            timeout
        }
    }

    pub fn add_peer(
        &self,
        local_key: &Arc<KeyId>,
        peer_ip_address: &IpAddress,
        peer_key: &Arc<KeyOption>,
    ) -> Result<Option<Arc<KeyId>>> {
        use dashmap::mapref::entry::Entry;

        if peer_key.id() == local_key {
            return Ok(None);
        }

        let id = peer_key.id().clone();

        match self.peers(local_key)?.entry(id.clone()) {
            Entry::Occupied(entry) => {
                entry
                    .get()
                    .address
                    .ip_address
                    .store(peer_ip_address.0, atomic::Ordering::Release);
            }
            Entry::Vacant(entry) => {
                let address =
                    AdnlNodeAddress::from_ip_address_and_key(*peer_ip_address, peer_key.clone())?;

                entry.insert(Peer {
                    address,
                    receiver_state: PeerState::for_receive_with_reinit_date(self.start_time),
                    sender_state: PeerState::for_send(),
                });

                log::debug!(
                    "Added ADNL peer with keyID {}, key {} to {}",
                    base64::encode(peer_key.id().data()),
                    base64::encode(peer_key.pub_key()?),
                    base64::encode(local_key.data())
                )
            }
        };

        Ok(Some(id))
    }

    pub fn delete_peer(&self, local_key: &Arc<KeyId>, peer_key: &Arc<KeyId>) -> Result<bool> {
        let peers = self.peers.get(local_key).ok_or_else(|| {
            ton_types::error!(
                "Try to remove peer {} from unknown local key {}",
                peer_key,
                local_key
            )
        })?;
        Ok(peers.value().remove(peer_key).is_some())
    }

    fn peers(&self, src: &Arc<KeyId>) -> Result<Arc<Peers>> {
        if let Some(peers) = self.peers.get(src) {
            Ok(peers.value().clone())
        } else {
            fail!("Cannot get peers list for unknown local key {}", src)
        }
    }

    async fn process(
        &self,
        subscribers: &[Arc<dyn Subscriber>],
        message: &AdnlMessage,
        peers: &AdnlPeers,
    ) -> Result<()> {
        use dashmap::mapref::entry::Entry;

        let new_message = if let AdnlMessage::Adnl_Message_Part(part) = message {
            let transfer_id = get256(&part.hash);
            let (added, transfer) = match self.transfers.entry(*transfer_id) {
                Entry::Vacant(entry) => (
                    true,
                    entry
                        .insert(Arc::new(Transfer {
                            data: DashMap::new(),
                            received: AtomicUsize::new(0),
                            total: part.total_size as usize,
                            updated: UpdatedAt::new(),
                        }))
                        .value()
                        .clone(),
                ),
                Entry::Occupied(entry) => (false, entry.get().clone()),
            };

            if added {
                tokio::spawn({
                    let transfers = self.transfers.clone();
                    let transfer = transfer.clone();
                    let transfer_id = *transfer_id;

                    async move {
                        loop {
                            tokio::time::sleep(Duration::from_secs(Self::TIMEOUT_TRANSFER)).await;
                            if transfer.updated.is_expired(Self::TIMEOUT_TRANSFER) {
                                if transfers.remove(&transfer_id).is_some() {
                                    log::debug!(
                                        "ADNL transfer {} timed out",
                                        base64::encode(&transfer_id)
                                    );
                                }
                                break;
                            }
                        }
                    }
                });
            }

            transfer.updated.refresh();
            transfer
                .data
                .insert(part.offset as usize, part.data.to_vec());
            transfer
                .received
                .fetch_add(part.data.len(), atomic::Ordering::Release);
            match Self::update_transfer(transfer_id, &transfer) {
                Ok(Some(message)) => {
                    self.transfers.remove(transfer_id);
                    Some(message)
                }
                Err(error) => {
                    self.transfers.remove(transfer_id);
                    return Err(error);
                }
                _ => return Ok(()),
            }
        } else {
            None
        };

        let message = match new_message.as_ref().unwrap_or(message) {
            AdnlMessage::Adnl_Message_Answer(answer) => {
                self.process_answer(answer, peers.other()).await?;
                None
            }
            AdnlMessage::Adnl_Message_ConfirmChannel(confirm) => {
                let mut local_public_key = Some(*get256(&confirm.peer_key));
                let channel = self.create_channel(
                    peers,
                    &mut local_public_key,
                    get256(&confirm.key),
                    "confirmation",
                )?;
                self.channels_send
                    .insert(peers.other().clone(), channel.clone());
                self.channels_receive.insert(*channel.receive_id(), channel);
                None
            }
            AdnlMessage::Adnl_Message_CreateChannel(create) => {
                let mut local_public_key = None;
                let channel = self.create_channel(
                    peers,
                    &mut local_public_key,
                    get256(&create.key),
                    "creation",
                )?;
                let message = match local_public_key {
                    Some(key) => ConfirmChannelMessage {
                        key: ton::int256(key),
                        peer_key: create.key,
                        date: create.date,
                    }
                    .into_boxed(),
                    None => fail!("INTERNAL ERROR: local key mismatch in channel creation"),
                };

                #[allow(clippy::or_fun_call)]
                self.channels_wait
                    .insert(peers.other().clone(), channel)
                    .or(self
                        .channels_send
                        .remove(peers.other())
                        .map(|(_, value)| value))
                    .and_then(|removed| self.channels_receive.remove(removed.receive_id()));
                Some(message)
            }
            AdnlMessage::Adnl_Message_Custom(custom) => {
                if !Query::process_custom(subscribers, custom, peers).await? {
                    fail!("No subscribers for custom message {:?}", custom)
                }
                None
            }
            AdnlMessage::Adnl_Message_Query(query) => {
                Self::process_query(subscribers, query, peers).await?
            }
            _ => fail!("Unsupported ADNL message {:?}", message),
        };

        if let Some(message) = message {
            self.send_message(message, peers)?;
        }

        Ok(())
    }

    async fn process_answer(&self, answer: &AdnlAnswerMessage, src: &Arc<KeyId>) -> Result<()> {
        let query_id = *get256(&answer.query_id);
        if !Self::update_query(&self.queries, query_id, Some(&answer.answer)).await? {
            fail!("Received answer from {} to unknown query {:?}", src, answer)
        }
        Ok(())
    }

    async fn process_query(
        subscribers: &[Arc<dyn Subscriber>],
        query: &AdnlQueryMessage,
        peers: &AdnlPeers,
    ) -> Result<Option<AdnlMessage>> {
        if let (true, answer) = Query::process_adnl(subscribers, query, peers).await? {
            Ok(answer)
        } else {
            fail!("No subscribers for query {:?}", query)
        }
    }

    /// Send query
    pub async fn query(
        &self,
        query: &TLObject,
        peers: &AdnlPeers,
        timeout: Option<u64>,
    ) -> Result<Option<TLObject>> {
        self.query_with_prefix(None, query, peers, timeout).await
    }

    /// Send query with prefix
    pub async fn query_with_prefix(
        &self,
        prefix: Option<&[u8]>,
        query: &TLObject,
        peers: &AdnlPeers,
        timeout: Option<u64>,
    ) -> Result<Option<TLObject>> {
        let (query_id, msg) = Query::build(prefix, query)?;
        let (ping, query) = Query::new();
        self.queries.insert(query_id, query);
        log::info!(
            "Sent query {:02x}{:02x}{:02x}{:02x}",
            query_id[0],
            query_id[1],
            query_id[2],
            query_id[3]
        );
        let channel = if peers.local() == peers.other() {
            self.queue_local_sender.send((msg, peers.local().clone()))?;
            None
        } else {
            let channel = self.channels_send.get(peers.other());
            self.send_message(msg, peers)?;
            channel
        };
        let queries = self.queries.clone();
        tokio::spawn(async move {
            let timeout = timeout.unwrap_or(Self::TIMEOUT_QUERY_MAX);
            log::info!(
                "Scheduling drop for query {:02x}{:02x}{:02x}{:02x} in {} ms",
                query_id[0],
                query_id[1],
                query_id[2],
                query_id[3],
                timeout
            );
            tokio::time::sleep(Duration::from_millis(timeout)).await;
            log::info!(
                "Try dropping query {:02x}{:02x}{:02x}{:02x}",
                query_id[0],
                query_id[1],
                query_id[2],
                query_id[3]
            );
            match Self::update_query(&queries, query_id, None).await {
                Err(e) => log::info!(
                    "ERROR: {} when dropping query {:02x}{:02x}{:02x}{:02x}",
                    e,
                    query_id[0],
                    query_id[1],
                    query_id[2],
                    query_id[3]
                ),
                Ok(true) => log::info!(
                    "Dropped query {:02x}{:02x}{:02x}{:02x}",
                    query_id[0],
                    query_id[1],
                    query_id[2],
                    query_id[3]
                ),
                _ => (),
            }
        });
        ping.wait().await;
        log::info!(
            "Finished query {:02x}{:02x}{:02x}{:02x}",
            query_id[0],
            query_id[1],
            query_id[2],
            query_id[3]
        );
        if let Some((_, removed)) = self.queries.remove(&query_id) {
            match removed {
                Query::Received(answer) => return Ok(Some(deserialize(&answer)?)),
                Query::Timeout => {
                    /* Monitor channel health */
                    if let Some(channel) = channel {
                        let now = now() as u32;
                        let was = channel
                            .value()
                            .drop
                            .compare_exchange(
                                0,
                                now + Self::TIMEOUT_CHANNEL_RESET,
                                atomic::Ordering::Acquire,
                                atomic::Ordering::Relaxed,
                            )
                            .unwrap_or_else(|was| was);
                        if (was > 0) && (was < now) {
                            self.reset_peers(peers)?
                        }
                    }
                    return Ok(None);
                }
                _ => (),
            }
        }
        fail!("INTERNAL ERROR: ADNL query mismatch")
    }

    /// Reset peers
    pub fn reset_peers(&self, peers: &AdnlPeers) -> Result<()> {
        let peer_list = self.peers(peers.local())?;
        let peer_entry = peer_list.get(peers.other()).ok_or_else(|| {
            ton_types::error!(
                "Try to reset unknown peer pair {} -> {}",
                peers.local(),
                peers.other()
            )
        })?;
        log::warn!("Resetting peer pair {} -> {}", peers.local(), peers.other());
        let peer = peer_entry.value();
        let address = AdnlNodeAddress::from_ip_address_and_key(
            IpAddress(peer.address.ip_address.load(atomic::Ordering::Acquire)),
            peer.address.key.clone(),
        )?;

        let reinit_data = peer
            .receiver_state
            .reinit_date
            .load(atomic::Ordering::Acquire);

        std::mem::drop(peer_entry);

        self.channels_wait
            .remove(peers.other())
            .or_else(|| self.channels_send.remove(peers.other()))
            .and_then(|(_, removed)| {
                peer_list.insert(
                    peers.other().clone(),
                    Peer {
                        address,
                        receiver_state: PeerState::for_receive_with_reinit_date(reinit_data + 1),
                        sender_state: PeerState::for_send(),
                    },
                );

                self.channels_receive.remove(removed.receive_id())
            });
        Ok(())
    }

    pub async fn send_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<()> {
        let msg = AdnlCustomMessage {
            data: ton::bytes(data.to_vec()),
        }
        .into_boxed();
        self.send_message(msg, peers)
    }

    async fn check_packet(
        &self,
        packet: &AdnlPacketContents,
        local_key: &Arc<KeyId>,
        other_key: Option<Arc<KeyId>>,
    ) -> Result<Option<Arc<KeyId>>> {
        let result = if let Some(other_key) = &other_key {
            if packet.from().is_some() || packet.from_short().is_some() {
                fail!("Explicit source address inside channel packet")
            }
            other_key.clone()
        } else if let Some(public_key) = packet.from() {
            let key = Arc::new(KeyOption::from_tl_public_key(public_key)?);
            let other_key = key.id().clone();
            if let Some(id) = packet.from_short() {
                if other_key.data() != &id.id.0 {
                    fail!("Mismatch between ID and key inside packet")
                }
            }
            if let Some(address) = packet.address() {
                let ip_address = parse_address_list(address)?;
                self.add_peer(&local_key, &ip_address, &key)?;
            }
            other_key
        } else if let Some(id) = packet.from_short() {
            KeyId::from_data(id.id.0)
        } else {
            fail!("No other key data inside packet: {:?}", packet);
        };

        let dst_reinit_date = packet.dst_reinit_date();
        let reinit_date = packet.reinit_date();

        if dst_reinit_date.is_some() != reinit_date.is_some() {
            fail!("Destination and source reinit dates mismatch");
        }

        let peer = self.peers(&local_key)?;
        let peer = if other_key.is_some() {
            if let Some(channel) = self.channels_send.get(&result) {
                peer.get(&channel.other_key)
            } else {
                fail!("Unknown channel, ID {:x?}", result);
            }
        } else {
            peer.get(&result)
        };

        let peer = match peer {
            Some(peer) => peer,
            None => fail!("Unknown peer {}", result),
        };

        if let (Some(&dst_reinit_date), Some(&reinit_date)) = (dst_reinit_date, reinit_date) {
            if dst_reinit_date != 0 {
                match dst_reinit_date.cmp(&peer.receiver_state.reinit_date()) {
                    Ordering::Equal => {}
                    Ordering::Greater => fail!(
                        "Destination reinit date is too new: {} vs {}, {:?}",
                        dst_reinit_date,
                        peer.receiver_state.reinit_date(),
                        packet
                    ),
                    Ordering::Less => fail!(
                        "Destination reinit date is too old: {} vs {}, {:?}",
                        dst_reinit_date,
                        peer.receiver_state.reinit_date(),
                        packet
                    ),
                }
            }

            let other_reinit_date = peer.sender_state.reinit_date();
            match reinit_date.cmp(&other_reinit_date) {
                Ordering::Equal => {}
                Ordering::Greater => {
                    if reinit_date > now() + Self::CLOCK_TOLERANCE {
                        fail!("Source reinit date is too new: {}", reinit_date);
                    } else {
                        peer.sender_state.reset_reinit_date(reinit_date);
                        if other_reinit_date != 0 {
                            peer.sender_state.reset_seqno(0).await?;
                            peer.receiver_state.reset_seqno(0).await?;
                        }
                    }
                }
                Ordering::Less => fail!("Source reinit date is too old: {}", reinit_date),
            }
        }

        if let Some(&seqno) = packet.seqno() {
            match peer.receiver_state.save_seqno(seqno as u64).await {
                Ok(false) => return Ok(None),
                Err(e) => fail!("Peer {} ({:?}): {}", result, other_key, e),
                _ => {}
            }
        }

        if let Some(&seqno) = packet.confirm_seqno() {
            let local_seqno = peer.sender_state.seqno();
            if seqno as u64 > local_seqno {
                fail!(
                    "Peer {}: too new ADNL packet seqno confirmed: {}, expected <= {}",
                    result,
                    seqno,
                    local_seqno
                )
            }
        }

        Ok(Some(result))
    }

    fn create_channel(
        &self,
        peers: &AdnlPeers,
        local_public_key: &mut Option<[u8; 32]>,
        other_public_key: &[u8; 32],
        context: &str,
    ) -> Result<Arc<AdnlChannel>> {
        let local_key = peers.local();
        let other_key = peers.other();
        let peer = self.peers(local_key)?;
        let peer = match peer.get(other_key) {
            Some(peer) => peer,
            None => fail!(
                "Channel {} with unknown peer {} -> {}",
                context,
                local_key,
                other_key
            ),
        };

        let channel_key = &peer.address.channel_key;
        let channel_public_key = channel_key.pub_key()?;
        if let Some(key) = local_public_key {
            if channel_public_key != key {
                fail!(
                    "Mismatch in key for channel {}\n{} / {}",
                    context,
                    base64::encode(channel_public_key),
                    base64::encode(other_public_key)
                )
            }
        } else {
            local_public_key.replace(*channel_public_key);
        }
        let channel = AdnlChannel::with_keys(local_key, channel_key, other_key, other_public_key)?;
        log::debug!("Channel {}: {} -> {}", context, local_key, other_key);
        log::trace!(
            "Channel send ID {}, recv ID {}",
            base64::encode(channel.send_id()),
            base64::encode(channel.receive_id())
        );
        Ok(Arc::new(channel))
    }

    async fn receive(
        &self,
        mut buffer: PacketView<'_>,
        subscribers: &[Arc<dyn Subscriber>],
    ) -> Result<()> {
        let (local_key, other_key) = if let Some(local_key) =
            AdnlHandshake::parse_packet(&self.config.keys, &mut buffer, None)?
        {
            (local_key, None)
        } else if let Some(channel) = self.channels_receive.get(&buffer.get()[0..32]) {
            let channel = channel.value();
            channel.decrypt_inplace(&mut buffer)?;
            if let Some((key, removed)) = self.channels_wait.remove(&channel.other_key) {
                self.channels_send.insert(key, removed);
            }

            channel.drop.store(0, atomic::Ordering::Release);
            (channel.local_key.clone(), Some(channel.other_key.clone()))
        } else {
            log::trace!(
                "Received message to unknown key ID {}",
                base64::encode(&buffer.get()[0..32])
            );
            return Ok(());
        };

        let packet = deserialize(buffer.get())?
            .downcast::<AdnlPacketContents>()
            .map_err(|packet| {
                failure::format_err!("Unsupported ADNL packet format {:?}", packet)
            })?;

        let other_key = match self.check_packet(&packet, &local_key, other_key).await? {
            Some(key) => key,
            None => return Ok(()),
        };

        let peers = AdnlPeers::with_keys(local_key, other_key);
        if let Some(message) = packet.message() {
            self.process(subscribers, message, &peers).await?;
        } else if let Some(messages) = packet.messages() {
            for message in messages.iter() {
                self.process(subscribers, message, &peers).await?;
            }
        }

        Ok(())
    }

    fn send_message(&self, message: AdnlMessage, peers: &AdnlPeers) -> Result<()> {
        let peer = self.peers(peers.local())?;
        let peer = match peer.get(peers.other()) {
            Some(peer) => peer,
            None => fail!("Unknown peer {}", peers.other()),
        };
        let peer = peer.value();

        let src = self.key_by_id(peers.local())?;
        let dst = peers.other();
        let channel = self.channels_send.get(dst);
        let create_channel_message = if channel.is_none() && self.channels_wait.get(dst).is_none() {
            log::debug!("Create channel {} -> {}", src.id(), dst);
            Some(
                CreateChannelMessage {
                    key: ton::int256(*peer.address.channel_key.pub_key()?),
                    date: now(),
                }
                .into_boxed(),
            )
        } else {
            None
        };

        let mut size = create_channel_message
            .is_some()
            .then(|| 40)
            .unwrap_or_default();

        size += match &message {
            AdnlMessage::Adnl_Message_Answer(answer) => answer.answer.len() + 44,
            AdnlMessage::Adnl_Message_ConfirmChannel(_) => 72,
            AdnlMessage::Adnl_Message_Custom(custom) => custom.data.len() + 12,
            AdnlMessage::Adnl_Message_Query(query) => query.query.len() + 44,
            _ => fail!("Unexpected message to send {:?}", message),
        };

        let channel = channel.as_ref().map(|channel| channel.value());

        if size <= Self::MAX_ADNL_MESSAGE_SIZE {
            if let Some(create_channel_message) = create_channel_message {
                self.send_packet(
                    peer,
                    &src,
                    channel,
                    None,
                    Some(vec![create_channel_message, message]),
                )
            } else {
                self.send_packet(peer, &src, channel, Some(message), None)
            }
        } else {
            if let Some(create_channel_message) = create_channel_message {
                self.send_packet(peer, &src, channel, Some(create_channel_message), None)?;
            }
            let data = serialize(&message)?;
            let hash = sha2::Sha256::digest(&data);

            let mut offset = 0;
            while offset < data.len() {
                let next_length = std::cmp::min(data.len(), offset + Self::MAX_ADNL_MESSAGE_SIZE);
                let mut part = Vec::new();
                part.extend_from_slice(&data[offset..next_length]);
                let part = AdnlPartMessage {
                    hash: ton::int256(*arrayref::array_ref!(hash.as_slice(), 0, 32)),
                    total_size: data.len() as i32,
                    offset: offset as i32,
                    data: ton::bytes(part),
                }
                .into_boxed();

                self.send_packet(peer, &src, channel, Some(part), None)?;
                offset = next_length;
            }

            Ok(())
        }
    }

    fn send_packet(
        &self,
        peer: &Peer,
        source: &KeyOption,
        channel: Option<&Arc<AdnlChannel>>,
        message: Option<AdnlMessage>,
        messages: Option<Vec<AdnlMessage>>,
    ) -> Result<()> {
        let mut data = serialize(
            &PacketContents {
                rand1: ton::bytes(gen_rand()),
                from: if channel.is_some() {
                    None
                } else {
                    Some(source.as_tl_public_key()?)
                },
                from_short: if channel.is_some() {
                    None
                } else {
                    Some(AdnlIdShort {
                        id: ton::int256(*source.id().data()),
                    })
                },
                message,
                messages: messages.map(From::from),
                address: Some(self.build_address_list(Some(now() + Self::TIMEOUT_ADDRESS))?),
                priority_address: None,
                seqno: Some(peer.sender_state.bump_seqno() as i64),
                confirm_seqno: Some(peer.receiver_state.seqno() as i64),
                recv_addr_list_version: None,
                recv_priority_addr_list_version: None,
                reinit_date: if channel.is_some() {
                    None
                } else {
                    Some(peer.receiver_state.reinit_date())
                },
                dst_reinit_date: if channel.is_some() {
                    None
                } else {
                    Some(peer.sender_state.reinit_date())
                },
                signature: None,
                rand2: ton::bytes(gen_rand()),
            }
            .into_boxed(),
        )?;

        if let Some(channel) = channel {
            channel.encrypt_inplace(&mut data)?;
        } else {
            let (_, key) = KeyOption::with_type_id(source.type_id())?;
            AdnlHandshake::build_packet(&mut data, &key, &peer.address.key)?;
        }

        self.queue_sender.send(Job::Send(SendJob {
            destination: peer.address.ip_address.load(atomic::Ordering::Acquire),
            data,
        }))?;

        Ok(())
    }

    async fn update_query(
        queries: &Arc<QueryCache>,
        query_id: QueryId,
        answer: Option<&ton::bytes>,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        let old = match queries.entry(query_id) {
            Entry::Vacant(_) => None,
            Entry::Occupied(entry) => match entry.get() {
                Query::Sent(_) => {
                    let (_, old) = entry.replace_entry(match answer {
                        Some(bytes) => Query::Received(bytes.to_vec()),
                        None => Query::Timeout,
                    });
                    Some(old)
                }
                _ => None,
            },
        };

        let removed = match old {
            Some(query) => query,
            None => return Ok(false),
        };

        if let Query::Sent(pong) = removed {
            pong.wait().await;
        } else {
            fail!(
                "INTERNAL ERROR: ADNL query state mismatch, \
                 expected Query::Sent, found {:?}",
                removed
            )
        }
        Ok(true)
    }

    fn update_transfer(
        transfer_id: &TransferId,
        transfer: &Arc<Transfer>,
    ) -> Result<Option<AdnlMessage>> {
        let mut received = transfer
            .received
            .compare_exchange(
                transfer.total,
                2 * transfer.total,
                atomic::Ordering::Release,
                atomic::Ordering::Relaxed,
            )
            .unwrap_or_else(|was| was);

        if received > transfer.total {
            fail!(
                "Invalid ADNL part transfer: size mismatch {} vs. total {}",
                received,
                transfer.total
            )
        }

        if received == transfer.total {
            log::debug!("Finished ADNL part {} (total {})", received, transfer.total);
            received = 0;
            let mut buffer = Vec::with_capacity(transfer.total);
            while received < transfer.total {
                if let Some(data) = transfer.data.get(&received) {
                    let data = data.value();
                    received += data.len();
                    buffer.extend_from_slice(data);
                } else {
                    fail!("Invalid ADNL part transfer: parts mismatch")
                }
            }
            let hash = sha2::Sha256::digest(&buffer);
            if arrayref::array_ref!(hash.as_slice(), 0, 32) != transfer_id {
                fail!("Bad hash of ADNL transfer {}", base64::encode(transfer_id))
            }
            let msg = deserialize(&buffer)?
                .downcast::<AdnlMessage>()
                .map_err(|msg| ton_types::error!("Unsupported ADNL messge {:?}", msg))?;
            Ok(Some(msg))
        } else {
            log::debug!("Received ADNL part {} (total {})", received, transfer.total);
            Ok(None)
        }
    }
}

pub struct AdnlNodeConfig {
    ip_address: IpAddress,
    keys: DashMap<Arc<KeyId>, Arc<KeyOption>>,
    tags: DashMap<usize, Arc<KeyId>>,
    throughput: Option<u32>,
}

impl AdnlNodeConfig {
    /// Construct from IP address and key data
    pub fn from_ip_address_and_keys(
        ip_address: SocketAddr,
        keys: Vec<(KeyOption, usize)>,
    ) -> Result<Self> {
        let ret = AdnlNodeConfig {
            ip_address: IpAddress::from_socket_address(ip_address)?,
            keys: DashMap::new(),
            tags: DashMap::new(),
            throughput: None,
        };
        for (key, tag) in keys {
            ret.add_key(key, tag)?;
        }
        Ok(ret)
    }

    pub fn ip_address(&self) -> IpAddress {
        self.ip_address
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

        let result = key.id().clone();

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
                Entry::Vacant(entry) => {
                    entry.insert(key);
                }
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
    ip_address: AtomicU64,
    key: Arc<KeyOption>,
}

impl AdnlNodeAddress {
    fn from_ip_address_and_key(ip_address: IpAddress, key: Arc<KeyOption>) -> Result<Self> {
        let channel_key = KeyOption::with_type_id(key.type_id())?.1;
        Ok(Self {
            channel_key: Arc::new(channel_key),
            ip_address: AtomicU64::new(ip_address.0),
            key,
        })
    }
}
/// ADNL addresses cache iterator
#[derive(Debug)]
pub struct AddressCacheIterator(u32);

/// ADNL addresses cache
pub struct AddressCache {
    cache: DashMap<Arc<KeyId>, u32>,
    index: DashMap<u32, Arc<KeyId>>,
    limit: u32,
    upper: AtomicU32,
}

impl AddressCache {
    pub fn with_limit(limit: u32) -> Self {
        Self {
            cache: DashMap::new(),
            index: DashMap::new(),
            limit,
            upper: AtomicU32::new(0),
        }
    }

    pub fn contains(&self, address: &Arc<KeyId>) -> bool {
        self.cache.get(address).is_some()
    }

    pub fn count(&self) -> u32 {
        std::cmp::min(self.upper.load(atomic::Ordering::Acquire), self.limit)
    }

    pub fn first(&self) -> (AddressCacheIterator, Option<Arc<KeyId>>) {
        (AddressCacheIterator(0), self.find_by_index(0))
    }

    pub fn given(&self, iter: &AddressCacheIterator) -> Option<Arc<KeyId>> {
        let AddressCacheIterator(ref index) = iter;
        self.find_by_index(*index)
    }

    pub fn next(&self, iter: &mut AddressCacheIterator) -> Option<Arc<KeyId>> {
        let AddressCacheIterator(ref mut index) = iter;
        loop {
            let ret = self.find_by_index({
                *index += 1;
                *index
            });
            if ret.is_some() {
                return ret;
            }
            let limit = self.upper.load(atomic::Ordering::Acquire);
            if *index >= std::cmp::min(limit, self.limit) {
                return None;
            }
        }
    }

    pub fn put(&self, address: Arc<KeyId>) -> Result<bool> {
        use dashmap::mapref::entry::Entry;

        Ok(match self.cache.entry(address.clone()) {
            Entry::Vacant(entry) => {
                let upper = self.upper.fetch_add(1, atomic::Ordering::Acquire);
                let mut index = upper;
                if index >= self.limit {
                    if index >= self.limit * 2 {
                        self.upper
                            .compare_exchange(
                                upper + 1,
                                index - self.limit + 1,
                                atomic::Ordering::Release,
                                atomic::Ordering::Relaxed,
                            )
                            .ok();
                    }
                    index %= self.limit;
                }
                entry.insert(index);
                if let Some(key) = self.index.insert(index, address) {
                    self.cache
                        .remove_if(&key, |_, &old_index| old_index == index);
                }
                true
            }
            Entry::Occupied(_) => false,
        })
    }

    pub fn random_set(
        &self,
        dst: &AddressCache,
        skip: Option<&DashSet<Arc<KeyId>>>,
        n: u32,
    ) -> Result<()> {
        let mut n = std::cmp::min(self.count(), n);
        while n > 0 {
            if let Some(key_id) = self.random(skip) {
                // We do not check success of put due to multithreading
                dst.put(key_id)?;
                n -= 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    pub fn random_vec(&self, skip: Option<&Arc<KeyId>>, n: u32) -> Vec<Arc<KeyId>> {
        use rand::Rng;

        let max = self.count();
        let mut ret = Vec::new();
        let mut check = false;
        let mut i = std::cmp::min(max, n);
        while i > 0 {
            if let Some(key_id) = self.index.get(&rand::thread_rng().gen_range(0, max)) {
                let key_id = key_id.value();
                if let Some(skip) = skip {
                    if skip == key_id {
                        // If there are not enough items in cache,
                        // reduce limit for skipped element
                        if (n >= max) && !check {
                            check = true;
                            i -= 1;
                        }
                        continue;
                    }
                }
                if ret.contains(key_id) {
                    continue;
                } else {
                    ret.push(key_id.clone());
                    i -= 1;
                }
            }
        }
        ret
    }

    fn find_by_index(&self, index: u32) -> Option<Arc<KeyId>> {
        self.index
            .get(&index)
            .map(|address| address.value().clone())
    }

    fn random(&self, skip: Option<&DashSet<Arc<KeyId>>>) -> Option<Arc<KeyId>> {
        use rand::Rng;

        let max = self.count();
        // We need a finite loop here because we can test skip set only on case-by-case basis
        // due to multithreading. So it is possible that all items shall be skipped, and with
        // infinite loop we will simply hang
        for _ in 0..10 {
            if let Some(ret) = self.index.get(&rand::thread_rng().gen_range(0, max)) {
                let ret = ret.value();
                if let Some(skip) = skip {
                    if skip.contains(ret) {
                        continue;
                    }
                }
                return Some(ret.clone());
            }
        }
        None
    }
}

struct AdnlChannel {
    local_key: Arc<KeyId>,
    other_key: Arc<KeyId>,
    drop: AtomicU32,
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
            let mut reversed_secret = forward_secret;
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
            drop: Default::default(),
            receive_channel: ChannelSide::from_secret(forward_secret)?,
            send_channel: ChannelSide::from_secret(reversed_secret)?,
        })
    }

    fn decrypt_inplace(&self, buffer: &mut PacketView) -> Result<()> {
        if buffer.get().len() < 64 {
            fail!("Channel message is too short: {}", buffer.get().len())
        }
        Self::process_data_inplace(buffer.get_mut(), &self.receive_channel.secret);
        if sha2::Sha256::digest(&buffer.get()[64..]).as_slice() != &buffer.get()[32..64] {
            fail!("Bad channel message checksum");
        }
        buffer.remove_prefix(64);
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

    fn process_data_inplace(buffer: &mut [u8], secret: &[u8; 32]) {
        let digest = &buffer[32..64];
        let mut key = crate::from_slice!(secret, 0, 16, digest, 16, 16);
        let mut ctr = crate::from_slice!(digest, 0, 4, secret, 20, 12);
        AdnlCryptoUtils::build_cipher_secure(&mut key[..], &mut ctr[..])
            .apply_keystream(&mut buffer[64..])
    }

    fn receive_id(&self) -> &ChannelId {
        &self.receive_channel.id
    }

    fn send_id(&self) -> &ChannelId {
        &self.send_channel.id
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
        Self::from_socket_address(str.parse::<SocketAddr>()?)
    }

    pub fn from_socket_address(addr: SocketAddr) -> Result<Self> {
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
        self.0 as u16
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
            self.0 >> 40u8,
            self.0 >> 32u8,
            self.0 >> 24u8,
            self.0 >> 16u8,
            self.0 as u16
        )
    }
}

struct Transfer {
    data: DashMap<usize, Vec<u8>>,
    received: AtomicUsize,
    total: usize,
    updated: UpdatedAt,
}

type ChannelId = [u8; 32];

fn calc_channel_id(secret: &[u8; 32]) -> Result<ChannelId> {
    hash(AesKey {
        key: ton::int256(*secret),
    })
}

#[derive(Debug)]
enum Job {
    Send(SendJob),
    Stop,
}

#[derive(Debug)]
struct SendJob {
    destination: u64,
    data: Vec<u8>,
}

struct Peer {
    address: AdnlNodeAddress,
    receiver_state: PeerState,
    sender_state: PeerState,
}

const HISTORY_BITS: usize = 512;
const HISTORY_CELLS: usize = HISTORY_BITS / 64;

pub struct PeerHistory {
    index: AtomicU64,
    masks: [AtomicU64; HISTORY_CELLS],
    seqno: AtomicU64,
}

impl Default for PeerHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerHistory {
    const INDEX_MASK: u64 = HISTORY_BITS as u64 / 2 - 1;
    const IN_TRANSIT: u64 = 0xFFFFFFFFFFFFFFFF;

    pub fn new() -> Self {
        Self {
            index: AtomicU64::new(0),
            masks: Default::default(),
            seqno: AtomicU64::new(0),
        }
    }

    pub fn print_stats(&self) {
        let seqno = self.seqno.load(atomic::Ordering::Relaxed);
        log::info!(
            "Peer history: seqno {}/{:x}, mask {:x} [ {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x} ]",
            seqno,
            seqno,
            self.index.load(atomic::Ordering::Relaxed),
            self.masks[0].load(atomic::Ordering::Relaxed),
            self.masks[1].load(atomic::Ordering::Relaxed),
            self.masks[2].load(atomic::Ordering::Relaxed),
            self.masks[3].load(atomic::Ordering::Relaxed),
            self.masks[4].load(atomic::Ordering::Relaxed),
            self.masks[5].load(atomic::Ordering::Relaxed),
            self.masks[6].load(atomic::Ordering::Relaxed),
            self.masks[7].load(atomic::Ordering::Relaxed)
        )
    }

    pub async fn update(&self, seqno: u64) -> Result<bool> {
        let seqno_masked = seqno & Self::INDEX_MASK;
        let seqno_normalized = seqno & !Self::INDEX_MASK;
        loop {
            let index = self.index.load(atomic::Ordering::Acquire);
            if index == Self::IN_TRANSIT {
                tokio::task::yield_now().await;
                continue;
            }

            let index_masked = index & Self::INDEX_MASK;
            let index_normalized = index & !Self::INDEX_MASK;
            if index_normalized > seqno_normalized + Self::INDEX_MASK + 1 {
                // Out of the window
                log::trace!(
                    "Peer packet with seqno {:x} is too old ({:x})",
                    seqno,
                    index_normalized
                );
                return Ok(false);
            }

            let mask = 1 << (seqno_normalized % 64);
            let mask_offset = match index_normalized.cmp(&seqno_normalized) {
                // Lower part of the window
                Ordering::Greater => Some(0),
                // Upper part of the window
                Ordering::Equal => Some(HISTORY_CELLS / 2),
                // Out of the window
                Ordering::Less => None,
            };

            let next_index = if let Some(mask_offset) = mask_offset {
                let mask_offset = mask_offset + seqno_masked as usize / 64;
                let already_received =
                    self.masks[mask_offset].load(atomic::Ordering::Acquire) & mask;
                if self.index.load(atomic::Ordering::Acquire) != index {
                    log::warn!("ADNL4");
                    continue;
                }

                if already_received != 0 {
                    log::trace!("Peer packet with seqno {:x} was already received", seqno);
                    return Ok(false);
                }

                if self
                    .index
                    .compare_exchange(
                        index,
                        Self::IN_TRANSIT,
                        atomic::Ordering::Release,
                        atomic::Ordering::Relaxed,
                    )
                    .is_err()
                {
                    log::warn!("ADNL5");
                    continue;
                }

                self.masks[mask_offset].fetch_or(mask, atomic::Ordering::Release);
                index
            } else {
                if self
                    .index
                    .compare_exchange(
                        index,
                        Self::IN_TRANSIT,
                        atomic::Ordering::Release,
                        atomic::Ordering::Relaxed,
                    )
                    .is_err()
                {
                    log::warn!("ADNL6");
                    continue;
                }

                if index_normalized + Self::IN_TRANSIT + 1 == seqno_normalized {
                    for i in 0..HISTORY_CELLS / 2 {
                        self.masks[i].store(
                            self.masks[i + HISTORY_CELLS / 2].load(atomic::Ordering::Acquire),
                            atomic::Ordering::Release,
                        )
                    }
                    for i in HISTORY_CELLS / 2..HISTORY_CELLS {
                        self.masks[i].store(0, atomic::Ordering::Release)
                    }
                } else {
                    for i in 0..HISTORY_CELLS {
                        self.masks[i].store(0, atomic::Ordering::Release)
                    }
                }

                seqno_normalized
            };

            let last_seqno = self.seqno.load(atomic::Ordering::Acquire);
            if last_seqno < seqno {
                self.seqno.store(seqno, atomic::Ordering::Release);
            }

            let index_masked = (index_masked + 1) & !Self::INDEX_MASK;
            if self
                .index
                .compare_exchange(
                    Self::IN_TRANSIT,
                    index_masked | next_index,
                    atomic::Ordering::Release,
                    atomic::Ordering::Relaxed,
                )
                .is_err()
            {
                fail!(
                    "INTERNAL ERROR: Peer packet seqno sync mismatch ({:x})",
                    seqno
                )
            }
            break;
        }
        Ok(true)
    }

    async fn reset(&self, seqno: u64) -> Result<()> {
        loop {
            let index = self.index.load(atomic::Ordering::Acquire);
            if index == Self::IN_TRANSIT {
                tokio::task::yield_now().await;
                continue;
            }
            if self
                .index
                .compare_exchange(
                    index,
                    Self::IN_TRANSIT,
                    atomic::Ordering::Release,
                    atomic::Ordering::Relaxed,
                )
                .is_err()
            {
                continue;
            }
            break;
        }

        for i in 0..HISTORY_CELLS {
            self.masks[i].store(
                if i == HISTORY_CELLS / 2 { 1 } else { 0 },
                atomic::Ordering::Release,
            )
        }

        self.seqno.store(seqno, atomic::Ordering::Release);
        if self
            .index
            .compare_exchange(
                Self::IN_TRANSIT,
                seqno & !Self::INDEX_MASK,
                atomic::Ordering::Release,
                atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            fail!(
                "INTERNAL ERROR: peer packet seqno reset mismatch ({:x})",
                seqno
            )
        }
        Ok(())
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
            .store(reinit_date, atomic::Ordering::Release)
    }

    async fn reset_seqno(&self, seqno: u64) -> Result<()> {
        self.history.reset(seqno).await
    }

    async fn save_seqno(&self, seqno: u64) -> Result<bool> {
        self.history.update(seqno).await
    }
}

pub fn parse_address_list(list: &AddressList) -> Result<IpAddress> {
    if list.addrs.is_empty() {
        fail!("Empty address list")
    }

    let version = now();
    if (list.version > version) || (list.reinit_date > version) {
        fail!(
            "Address list version is too high: {} vs {}",
            list.version,
            version
        )
    }
    if (list.expire_at != 0) && (list.expire_at < version) {
        fail!("Address list is expired")
    }

    Ok(match &list.addrs[0] {
        Address::Adnl_Address_Udp(x) => IpAddress::from_ip_and_port(x.ip as u32, x.port as u16),
        _ => fail!("Only IPv4 address format is supported"),
    })
}

pub struct AdnlPingSubscriber;

#[async_trait::async_trait]
impl Subscriber for AdnlPingSubscriber {
    async fn try_consume_query(&self, object: TLObject, _peers: &AdnlPeers) -> Result<QueryResult> {
        match object.downcast::<AdnlPing>() {
            Ok(ping) => QueryResult::consume(AdnlPong { value: ping.value }),
            Err(object) => Ok(QueryResult::Rejected(object)),
        }
    }
}

fn gen_rand() -> Vec<u8> {
    use rand::Rng;

    const RAND_SIZE: usize = 16;

    let mut result = vec![0; RAND_SIZE];
    rand::thread_rng().fill(&mut result[..]);
    result
}

type ChannelsReceive = DashMap<ChannelId, Arc<AdnlChannel>>;
type ChannelsSend = DashMap<Arc<KeyId>, Arc<AdnlChannel>>;
type Peers = DashMap<Arc<KeyId>, Peer>;
type TransferId = [u8; 32];
