//! Development CLI for pairing and syncing vaults over the network.
//!
//! It exists to exercise the transport with real processes; it is not the
//! product interface. The vault password is read from `OSM_PASSWORD`. Output
//! lines start with a keyword so scripts and tests can follow along:
//!
//! ```text
//! osm-peer create <vault>
//! osm-peer add <vault> <title>
//! osm-peer list <vault>                                ITEM <title>
//! osm-peer invite <vault> <peers.db> <listen-addr>     LISTEN, INVITE, SAS, PAIRED
//! osm-peer join <code> <vault> <peers.db>              SAS, JOINED
//! osm-peer serve <vault> <peers.db> <listen-addr>      LISTEN, SYNCED
//! osm-peer sync <vault> <peers.db> <address>           SYNCED
//! osm-peer serve-locked <vault> <peers.db> <listen>    LISTEN, SYNCED
//! osm-peer sync-locked <vault> <peers.db> <address>    SYNCED
//! osm-peer device <vault> <peers.db> <control.db> <listen-addr|->
//! osm-peer join-device <code> <vault> <peers.db> <control.db> <listen-addr>
//! ```
//!
//! The `-locked` forms open the vault without its password: received
//! revisions are staged unverified and processed at the next unlock. Every
//! command that unlocks processes staged revisions first and prints
//! `PROCESSED` when there were any.
//!
//! `invite` and `join` are the interim pairing of two devices. They print
//! the short code and wait for `y` on stdin: the owner must compare the
//! codes on both devices before either confirms.
//!
//! `device` runs one device of a vault with a control plane until `quit`
//! or the end of stdin: its control-plane node, a listener for the other
//! members (none with `-`), and a loop that keeps the vault in line with
//! committed membership and grants new members the epoch keys. It prints
//! `READY <device>` and then takes commands on stdin, one per line:
//!
//! ```text
//! found                 FOUNDED
//! invite                INVITE, SAS (answer y), ENROLLING, ENROLLED <device>
//! add <title>           ADDED
//! list                  ITEM <title>..., LISTED
//! sync [<device>]       SYNCED or SYNC-FAILED per member, SYNC-DONE
//! remove <device>       REMOVED <device>
//! status                STATUS epoch= vault_epoch= members= held= staged= removed=
//! listen <addr>         LISTEN <addr>
//! quit
//! ```
//!
//! A command that fails prints `FAILED <command>: <reason>` and the device
//! keeps running. `join-device` pairs with an inviting device (`SAS`, answer
//! `y`), waits to be enrolled, creates its vault, prints `JOINED <device>`,
//! and then runs as `device` does. Devices are named by their 32-digit hex
//! IDs.

use std::{
    io::BufRead,
    process::ExitCode,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use osm_vault_core::{Item, Vault};
use osm_vault_membership::{
    device_id_from_bytes, device_id_to_bytes, ControlNode, DeviceId, NodeOptions,
};
use osm_vault_peer::{
    accept_pairing, connect_sync, control, invite, serve_members, serve_sync, start_node,
    start_pairing, AddressBook, Invitation, MemberEndpoint, MemberSync, PairingListener, PeerStore,
    SyncReport, MAX_INVITATION_TTL_SECS,
};
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex},
};

type CliResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String]) -> CliResult {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["create", vault] => {
            Vault::create(vault, &password()?)?;
            Ok(())
        }
        ["add", vault, title] => {
            let mut vault = unlock(vault)?;
            vault.put(Item::new(*title))?;
            Ok(())
        }
        ["list", vault] => {
            for item in unlock(vault)?.list()? {
                println!("ITEM {}", item.title);
            }
            Ok(())
        }
        ["invite", vault, peers, listen] => {
            let mut vault = unlock(vault)?;
            let mut peers = PeerStore::open(peers)?;
            // Invitations live only as long as this process waits for a joiner.
            let mut invitations = InvitationStore::open_in_memory(InvitationPolicy::default())?;
            let listener = PairingListener::bind(listen, &mut peers).await?;
            let address = listener.local_addr()?.to_string();
            println!("LISTEN {address}");
            let invitation = invite(
                &vault,
                &mut invitations,
                &mut peers,
                vec![address],
                now(),
                MAX_INVITATION_TTL_SECS,
            )?;
            println!("INVITE {}", invitation.encode()?.as_str());
            accept_pairing(
                &listener,
                &mut vault,
                &mut invitations,
                &mut peers,
                |sas| async move {
                    println!("SAS {sas}");
                    confirmed().await
                },
                now,
            )
            .await?;
            println!("PAIRED");
            Ok(())
        }
        ["join", code, vault, peers] => {
            let mut peers = PeerStore::open(peers)?;
            let connection = start_pairing(Invitation::decode(code)?, &mut peers, now()).await?;
            println!("SAS {}", connection.sas());
            let owner_confirmed = confirmed().await;
            let (joiner, grant) = connection.receive_grant().await?;
            joiner.finish(
                &grant,
                owner_confirmed,
                vault,
                &password()?,
                &mut peers,
                now(),
            )?;
            println!("JOINED");
            Ok(())
        }
        ["serve" | "serve-locked", vault, peers, listen] => {
            let mut vault = if args[0] == "serve" {
                unlock(vault)?
            } else {
                Vault::open(vault)?
            };
            let mut peers = PeerStore::open(peers)?;
            let listener = TcpListener::bind(listen).await?;
            println!("LISTEN {}", listener.local_addr()?);
            report(&serve_sync(&listener, &mut vault, &mut peers).await?);
            Ok(())
        }
        ["sync" | "sync-locked", vault, peers, address] => {
            let mut vault = if args[0] == "sync" {
                unlock(vault)?
            } else {
                Vault::open(vault)?
            };
            let mut peers = PeerStore::open(peers)?;
            report(&connect_sync(address, &mut vault, &mut peers).await?);
            Ok(())
        }
        ["device", vault, peers, control, listen] => {
            let vault = unlock(vault)?;
            let mut peers = PeerStore::open(peers)?;
            let device = device_id_from_bytes(vault.device_id().ok_or("the vault has no device")?);
            let (endpoint, node) = start_control(
                vault.vault_id(),
                device,
                &mut peers,
                peers_path(&args),
                control,
            )
            .await?;
            let device = Device::new(vault, peers, endpoint, node);
            if *listen != "-" {
                device.listen(listen).await?;
            }
            device.run(stdin_lines()).await
        }
        ["join-device", code, vault, peers, control, listen] => {
            let mut lines = stdin_lines();
            let mut peers = PeerStore::open(peers)?;
            let connection = start_pairing(Invitation::decode(code)?, &mut peers, now()).await?;
            println!("SAS {}", connection.sas());
            // The node runs from the start so that the leader can bring it
            // up to date; it accepts no one until the grant names members.
            let id = connection.joiner().control_device();
            let vault_id = connection.joiner().vault_id();
            let (endpoint, node) =
                start_control(vault_id, id, &mut peers, peers_path(&args), control).await?;
            let (sync, incoming) = mpsc::channel(4);
            serve(listen, &endpoint, &node, &sync).await?;
            let owner_confirmed = lines.recv().await.as_deref() == Some("y");
            let (joiner, grant) = connection.receive_enrollment().await?;
            endpoint.introduce(&joiner.members(&grant)?)?;
            let deadline = tokio::time::Instant::now() + ENROLLMENT_TIMEOUT;
            while !joiner.enrolled(&node.state()) {
                if tokio::time::Instant::now() > deadline {
                    return Err("this device was not enrolled in time".into());
                }
                // Until a member has reached this device, keep telling them
                // where it listens.
                endpoint.announce_all().await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let vault = joiner.finish_enrollment(
                &grant,
                owner_confirmed,
                &node.state(),
                vault,
                &password()?,
            )?;
            println!("JOINED {}", hex(id));
            let device = Device {
                sync,
                incoming: Mutex::new(Some(incoming)),
                ..Device::new(vault, peers, endpoint, node)
            };
            device.run(lines).await
        }
        _ => Err("unknown command; see the module documentation".into()),
    }
}

/// How long an inviter waits for a joiner to become a voter, and a joiner
/// to be enrolled and given the keys.
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(120);

/// The peer store path of a `device` or `join-device` command line. The
/// address book is kept in the same file.
fn peers_path<'a>(args: &[&'a str]) -> &'a str {
    match args {
        ["device", _, peers, ..] | ["join-device", _, _, peers, ..] => peers,
        _ => "",
    }
}

/// Starts this device's endpoint and control-plane node.
async fn start_control(
    vault_id: [u8; 32],
    device: DeviceId,
    peers: &mut PeerStore,
    peers_path: &str,
    control: &str,
) -> Result<(MemberEndpoint, Arc<ControlNode>), Box<dyn std::error::Error>> {
    let endpoint = MemberEndpoint::new(vault_id, peers, AddressBook::open(peers_path)?)?;
    let options = NodeOptions {
        write_timeout: Duration::from_secs(5),
        ..NodeOptions::default()
    };
    let node = start_node(control, device, &endpoint, options).await?;
    Ok((endpoint, node))
}

/// Binds `address`, serves members on it, and tells them where this device
/// now listens.
async fn serve(
    address: &str,
    endpoint: &MemberEndpoint,
    node: &Arc<ControlNode>,
    sync: &mpsc::Sender<MemberSync>,
) -> CliResult {
    let listener = TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    endpoint.set_listen_port(address.port());
    tokio::spawn(serve_members(
        listener,
        endpoint.clone(),
        node.clone(),
        Some(sync.clone()),
    ));
    println!("LISTEN {address}");
    endpoint.announce_all().await;
    Ok(())
}

type Lines = mpsc::UnboundedReceiver<String>;

/// Lines typed on stdin, read on a thread of their own.
fn stdin_lines() -> Lines {
    let (sender, lines) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if sender.send(line.trim().to_owned()).is_err() {
                break;
            }
        }
    });
    lines
}

fn hex(device: DeviceId) -> String {
    device_id_to_bytes(device)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_device(text: &str) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    if text.len() != 32 || !text.is_ascii() {
        return Err("a device ID is 32 hex digits".into());
    }
    let mut device = [0; 16];
    for (index, byte) in device.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
    }
    Ok(device)
}

/// One running device of a vault with a control plane.
struct Device {
    vault: Arc<Mutex<Vault>>,
    peers: Mutex<PeerStore>,
    invitations: Mutex<InvitationStore>,
    endpoint: MemberEndpoint,
    node: Arc<ControlNode>,
    /// Sync connections the listener took in, and where they are run.
    sync: mpsc::Sender<MemberSync>,
    incoming: Mutex<Option<mpsc::Receiver<MemberSync>>>,
}

impl Device {
    fn new(
        vault: Vault,
        peers: PeerStore,
        endpoint: MemberEndpoint,
        node: Arc<ControlNode>,
    ) -> Self {
        let (sync, incoming) = mpsc::channel(4);
        Self {
            vault: Arc::new(Mutex::new(vault)),
            peers: Mutex::new(peers),
            // Invitations live only as long as this process.
            invitations: Mutex::new(
                InvitationStore::open_in_memory(InvitationPolicy::default())
                    .expect("an in-memory invitation store opens"),
            ),
            endpoint,
            node,
            sync,
            incoming: Mutex::new(Some(incoming)),
        }
    }

    async fn listen(&self, address: &str) -> CliResult {
        serve(address, &self.endpoint, &self.node, &self.sync).await
    }

    /// Brings the vault in line with committed control state, applies what
    /// was waiting for it, and gives enrolled members the keys they lack.
    /// Run whenever the applied state changes.
    async fn catch_up(vault: &Mutex<Vault>, node: &ControlNode) {
        let state = node.state();
        let grants = {
            let mut vault = vault.lock().await;
            match control::reconcile(&mut vault, &state) {
                Ok(reconciled) => {
                    if let Some(epoch) = reconciled.activated {
                        println!("EPOCH {epoch}");
                    }
                }
                Err(error) => eprintln!("RECONCILE-FAILED {error}"),
            }
            let _ = vault.process_staged();
            control::grant_requests(&vault, &state).unwrap_or_default()
        };
        for request in grants {
            // Every member offers the same grant; all but one are refused
            // or recognized as already made.
            let _ = control::submit(node, request).await;
        }
    }

    /// Runs commands from `lines` until `quit` or the end of input.
    async fn run(self, mut lines: Lines) -> CliResult {
        println!("READY {}", hex(self.node.device()));
        let (vault, node) = (self.vault.clone(), self.node.clone());
        tokio::spawn(async move {
            let mut applied = node.subscribe();
            loop {
                Self::catch_up(&vault, &node).await;
                if applied.changed().await.is_err() {
                    return;
                }
            }
        });
        if let Some(mut incoming) = self.incoming.lock().await.take() {
            let (vault, node) = (self.vault.clone(), self.node.clone());
            tokio::spawn(async move {
                while let Some(connection) = incoming.recv().await {
                    let from = hex(connection.device());
                    let state = node.state();
                    let mut vault = vault.lock().await;
                    match connection.run(&mut vault, &state).await {
                        Ok(report) => println!("RECEIVED device={from} {}", counts(&report)),
                        Err(error) => println!("RECEIVE-FAILED device={from} {error}"),
                    }
                }
            });
        }
        while let Some(line) = lines.recv().await {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.first() == Some(&"quit") {
                break;
            }
            if let Err(error) = self.command(&words, &mut lines).await {
                println!("FAILED {}: {error}", words.first().unwrap_or(&""));
            }
        }
        self.node.shutdown().await;
        Ok(())
    }

    async fn command(&self, words: &[&str], lines: &mut Lines) -> CliResult {
        match words {
            ["found"] => {
                let vault = self.vault.lock().await;
                let mut peers = self.peers.lock().await;
                control::found(&vault, &mut peers, &self.node).await?;
                println!("FOUNDED");
            }
            ["invite"] => self.invite(lines).await?,
            ["add", title] => {
                self.vault.lock().await.put(Item::new(*title))?;
                println!("ADDED");
            }
            ["list"] => {
                for item in self.vault.lock().await.list()? {
                    println!("ITEM {}", item.title);
                }
                println!("LISTED");
            }
            ["sync", only @ ..] => {
                let only = match only {
                    [device] => Some(device_id_from_bytes(parse_device(device)?)),
                    _ => None,
                };
                let peers = match only {
                    Some(device) => vec![device],
                    None => self.endpoint.sync_peers(),
                };
                for device in peers {
                    match self.sync_with(device).await {
                        Ok(report) => {
                            println!("SYNCED device={} {}", hex(device), counts(&report))
                        }
                        Err(error) => println!("SYNC-FAILED device={} {error}", hex(device)),
                    }
                }
                println!("SYNC-DONE");
            }
            ["remove", device] => {
                let device = parse_device(device)?;
                let request = {
                    let vault = self.vault.lock().await;
                    control::removal_request(&vault, &self.node.state(), device)?
                };
                control::submit(&self.node, request).await?;
                println!("REMOVED {}", hex(device_id_from_bytes(device)));
            }
            ["status"] => {
                let state = self.node.state();
                let vault = self.vault.lock().await;
                println!(
                    "STATUS epoch={} vault_epoch={} members={} held={} staged={} removed={}",
                    state.epoch,
                    vault.current_epoch(),
                    state.members().len(),
                    vault.quarantined()?.len(),
                    vault.staged_revision_ids()?.len(),
                    self.endpoint.told_removed() || state.removed.contains_key(&self.node.device()),
                );
            }
            ["listen", address] => self.listen(address).await?,
            _ => return Err("unknown command".into()),
        }
        Ok(())
    }

    async fn sync_with(&self, device: DeviceId) -> Result<SyncReport, osm_vault_peer::Error> {
        let connection = self.endpoint.connect_sync(device).await?;
        let state = self.node.state();
        let mut vault = self.vault.lock().await;
        connection.run(&mut vault, &state).await
    }

    /// Invites one device: the owner compares the short codes and answers
    /// `y`, the enrollment is proposed to the vault's devices, and the
    /// joiner is told once they accept it.
    async fn invite(&self, lines: &mut Lines) -> CliResult {
        let listener = {
            let mut peers = self.peers.lock().await;
            PairingListener::bind("127.0.0.1:0", &mut peers).await?
        };
        let invitation = {
            let vault = self.vault.lock().await;
            let mut invitations = self.invitations.lock().await;
            let mut peers = self.peers.lock().await;
            invite(
                &vault,
                &mut invitations,
                &mut peers,
                vec![listener.local_addr()?.to_string()],
                now(),
                MAX_INVITATION_TTL_SECS,
            )?
        };
        println!("INVITE {}", invitation.encode()?.as_str());
        let pending = loop {
            let incoming = tokio::time::timeout(
                Duration::from_secs(MAX_INVITATION_TTL_SECS),
                listener.next_request(),
            )
            .await
            .map_err(|_| "the invitation expired")??;
            let vault = self.vault.lock().await;
            let invitations = self.invitations.lock().await;
            let mut peers = self.peers.lock().await;
            if let Ok(pending) = incoming.review(&vault, &invitations, &mut peers, now()) {
                break pending;
            }
        };
        println!("SAS {}", pending.sas());
        if lines.recv().await.as_deref() != Some("y") {
            pending.decline().await?;
            return Err("pairing was declined".into());
        }
        let joiner = device_id_from_bytes(pending.joiner_device_id());
        let (proposal, approved) = {
            let vault = self.vault.lock().await;
            let mut invitations = self.invitations.lock().await;
            pending.approve_enrollment(
                &vault,
                &mut invitations,
                self.endpoint.roster(),
                self.endpoint.listen_port(),
                now(),
            )?
        };
        if let Err(error) = control::submit(&self.node, proposal).await {
            approved.refuse().await?;
            return Err(error.into());
        }
        approved.send().await?;
        println!("ENROLLING {}", hex(joiner));
        let deadline = tokio::time::Instant::now() + ENROLLMENT_TIMEOUT;
        while !self.node.state().is_settled_member(joiner) {
            if tokio::time::Instant::now() > deadline {
                return Err("the new device did not catch up in time".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!("ENROLLED {}", hex(joiner));
        Ok(())
    }
}

fn counts(report: &SyncReport) -> String {
    format!(
        "sent={} received={} applied={} quarantined={} pending={}",
        report.sent, report.received, report.applied, report.quarantined, report.pending
    )
}

fn password() -> Result<String, Box<dyn std::error::Error>> {
    std::env::var("OSM_PASSWORD").map_err(|_| "set OSM_PASSWORD".into())
}

fn unlock(path: &str) -> Result<Vault, Box<dyn std::error::Error>> {
    let mut vault = Vault::open(path)?;
    vault.unlock(&password()?)?;
    if !vault.staged_revision_ids()?.is_empty() {
        let processed = vault.process_staged()?;
        println!(
            "PROCESSED applied={} quarantined={} rejected={} pending={}",
            processed.applied, processed.quarantined, processed.rejected, processed.pending
        );
    }
    Ok(vault)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Waits for the owner to type `y` after comparing the short codes.
async fn confirmed() -> bool {
    tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).is_ok() && line.trim() == "y"
    })
    .await
    .unwrap_or(false)
}

fn report(report: &SyncReport) {
    println!("SYNCED {}", counts(report));
}
