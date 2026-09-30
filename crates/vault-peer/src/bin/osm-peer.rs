//! Development CLI for pairing and syncing two vaults over the network.
//!
//! It exists to exercise the transport with real processes; it is not the
//! product interface. The vault password is read from `OSM_PASSWORD`. Output
//! lines start with a keyword so scripts and tests can follow along:
//!
//! ```text
//! osm-peer create <vault>
//! osm-peer add <vault> <title>
//! osm-peer list <vault>                              ITEM <title>
//! osm-peer invite <vault> <peers.db> <listen-addr>   LISTEN, INVITE, SAS, PAIRED
//! osm-peer join <code> <vault> <peers.db>            SAS, JOINED
//! osm-peer serve <vault> <peers.db> <listen-addr>    LISTEN, SYNCED
//! osm-peer sync <vault> <peers.db> <address>         SYNCED
//! ```
//!
//! `invite` and `join` print the short code and wait for `y` on stdin: the
//! owner must compare the codes on both devices before either confirms.

use std::{
    io::BufRead,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use osm_vault_core::{Item, Vault};
use osm_vault_peer::{
    accept_pairing, connect_sync, invite, serve_sync, start_pairing, Invitation, PeerStore,
    SyncReport, MAX_INVITATION_TTL_SECS,
};
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use tokio::net::TcpListener;

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
            let listener = TcpListener::bind(listen).await?;
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
        ["serve", vault, peers, listen] => {
            let mut vault = unlock(vault)?;
            let mut peers = PeerStore::open(peers)?;
            let listener = TcpListener::bind(listen).await?;
            println!("LISTEN {}", listener.local_addr()?);
            report(&serve_sync(&listener, &mut vault, &mut peers).await?);
            Ok(())
        }
        ["sync", vault, peers, address] => {
            let mut vault = unlock(vault)?;
            let mut peers = PeerStore::open(peers)?;
            report(&connect_sync(address, &mut vault, &mut peers).await?);
            Ok(())
        }
        _ => Err("unknown command; see the module documentation".into()),
    }
}

fn password() -> Result<String, Box<dyn std::error::Error>> {
    std::env::var("OSM_PASSWORD").map_err(|_| "set OSM_PASSWORD".into())
}

fn unlock(path: &str) -> Result<Vault, Box<dyn std::error::Error>> {
    let mut vault = Vault::open(path)?;
    vault.unlock(&password()?)?;
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
    println!(
        "SYNCED sent={} applied={} quarantined={} deferred={}",
        report.sent, report.applied, report.quarantined, report.deferred
    );
}
