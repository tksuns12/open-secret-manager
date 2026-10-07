//! What a vault costs the device it runs on: how long making a vault and
//! unlocking it take at the real password hashing cost (Argon2id, 64 MiB,
//! three passes), and the most memory the process held. For judging a
//! phone, or an app extension with a memory limit, against a desktop.
//!
//!   cargo run --release -p osm-vault-core --example unlock_cost -- [folder] [rounds] [items]
//!
//! The vault holds `items` items (100 if not given), one revision each. An
//! unlock reads every revision to check the rows of the file (format 8), so
//! its time grows with them.
//!
//! The peak memory is read from `/proc/self/status`, so it is reported on
//! Linux and Android only; elsewhere measure the process from outside.
use std::{path::PathBuf, time::Instant};

use osm_vault_core::{Item, Vault};

/// Not a secret: it opens only the vault made here, which is deleted.
const PASSWORD: &str = "a password for measuring, not a secret";

fn peak_memory() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .map(|line| line.trim_start_matches("VmHWM:").trim().to_owned())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let folder = args.next().map_or_else(std::env::temp_dir, PathBuf::from);
    let rounds: u32 = args.next().map_or(3, |text| text.parse().expect("rounds"));
    let items: u32 = args.next().map_or(100, |text| text.parse().expect("items"));
    let path = folder.join(format!("unlock-cost-{}.sqlite3", std::process::id()));

    let start = Instant::now();
    let (mut vault, _) = Vault::create(&path, PASSWORD).expect("create");
    println!("create: {} ms", start.elapsed().as_millis());
    let start = Instant::now();
    for n in 0..items {
        vault.put(Item::new(format!("Item {n}"))).expect("put");
    }
    println!("{items} items: {} ms", start.elapsed().as_millis());
    drop(vault);

    for _ in 0..rounds {
        let mut vault = Vault::open(&path).expect("open");
        let start = Instant::now();
        vault.unlock(PASSWORD).expect("unlock");
        let unlocked = start.elapsed();
        let start = Instant::now();
        let listed = vault.list().expect("list").len();
        println!(
            "unlock: {} ms, then listing {listed} items: {} ms",
            unlocked.as_millis(),
            start.elapsed().as_millis()
        );
    }
    println!(
        "peak memory: {}",
        peak_memory().unwrap_or_else(|| "not read here".into())
    );
    let _ = std::fs::remove_file(&path);
}
