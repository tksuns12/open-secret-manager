use std::{io::BufRead, path::PathBuf, process::ExitCode, sync::Arc, time::Duration};

use osm_browser_link::endpoint;
use osm_vault_browser::{bind, serve, Choices, Config, Desk, Refused};
use osm_vault_core::{Item, UnlockSession, Vault};
use tokio::sync::mpsc;

type CliResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::main]
pub async fn main() -> ExitCode {
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
            println!("CREATED");
            Ok(())
        }
        ["add", vault, title, username, password, address] => {
            let mut vault = unlock(vault)?;
            let mut item = Item::new(*title);
            item.username = (*username).into();
            item.password = (*password).into();
            item.url = (*address).into();
            println!("ADDED {}", item.id);
            vault.put(item)?;
            Ok(())
        }
        ["add-card", vault, title, cardholder, number, month, year, code] => {
            let mut vault = unlock(vault)?;
            let mut item = Item::new(*title);
            item.kind = osm_vault_core::ItemKind::Card;
            osm_vault_core::card::CardChange {
                cardholder: Some((*cardholder).into()),
                number: Some((*number).into()),
                expiry_month: Some((*month).into()),
                expiry_year: Some((*year).into()),
                security_code: Some((*code).into()),
                brand: None,
            }
            .apply_to(&mut item);
            println!("ADDED {}", item.id);
            vault.put(item)?;
            Ok(())
        }
        ["serve", vault, socket, options @ ..] => {
            let socket = match *socket {
                "-" => endpoint::socket_path().ok_or("this account has no data folder")?,
                path => PathBuf::from(path),
            };
            Owner::new(vault, options)?.serve(socket).await
        }
        _ => Err("usage: osm-fill create|add|add-card|serve ... (see the source header)".into()),
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

/// Lines typed on stdin, read on a thread of their own.
fn stdin_lines() -> mpsc::UnboundedReceiver<String> {
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Decide {
    First,
    Deny,
    Ask,
}

/// The owner's part, played by this process.
struct Owner {
    vault: Vault,
    decide: Decide,
    config: Config,
    /// The request last printed, and the unlock it was printed under.
    shown: Option<(String, Option<UnlockSession>)>,
}

impl Owner {
    fn new(vault: &str, options: &[&str]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut owner = Self {
            vault: Vault::open(vault)?,
            decide: Decide::Ask,
            config: Config::default(),
            shown: None,
        };
        let mut locked = false;
        for option in options {
            match *option {
                "first" => owner.decide = Decide::First,
                "deny" => owner.decide = Decide::Deny,
                "ask" => owner.decide = Decide::Ask,
                "locked" => locked = true,
                other => {
                    let seconds = other
                        .strip_prefix("within=")
                        .and_then(|seconds| seconds.parse().ok())
                        .ok_or_else(|| format!("unknown option {other}"))?;
                    owner.config.decide_within = Duration::from_secs(seconds);
                }
            }
        }
        if !locked {
            owner.vault.unlock(&password()?)?;
        }
        Ok(owner)
    }

    async fn serve(mut self, socket: PathBuf) -> CliResult {
        let desk = Desk::new(self.config);
        let bound = bind(&socket)?;
        println!("LISTENING {}", bound.path().display());
        let serving = tokio::spawn(serve(bound, desk.clone()));
        let mut changes = desk.changes();
        let mut lines = stdin_lines();
        loop {
            self.look(&desk)?;
            tokio::select! {
                changed = changes.changed() => changed?,
                line = lines.recv() => match line.as_deref() {
                    None | Some("quit") => break,
                    Some(line) => self.command(&desk, line)?,
                },
            }
        }
        // Stopping the session closes its connections and removes the
        // socket.
        serving.abort();
        let _ = serving.await;
        Ok(())
    }

    /// Prints what is waiting when that changed, and decides it if this
    /// process was told how.
    fn look(&mut self, desk: &Arc<Desk>) -> CliResult {
        let choices = desk.choices(Some(&self.vault))?;
        let now = choices
            .as_ref()
            .map(|choices| (choices.request_id.clone(), choices.session));
        if now == self.shown {
            return Ok(());
        }
        let Some(choices) = choices else {
            if let Some((request, _)) = self.shown.take() {
                println!("ENDED {request}");
            }
            return Ok(());
        };
        let offered = match &choices.card {
            Some(card) => card.cards.len(),
            None => choices.logins.len(),
        };
        println!(
            "REQUEST {} {} {} {}{}",
            choices.request_id,
            choices.origin,
            choices.browser,
            match choices.session {
                Some(_) => offered.to_string(),
                None => "locked".into(),
            },
            match &choices.card {
                Some(card) => format!(" card {}", card.frames.len()),
                None => String::new(),
            }
        );
        for login in &choices.logins {
            println!("LOGIN {} {}", login.id, login.title);
        }
        if let Some(card) = &choices.card {
            for frame in &card.frames {
                let fields: Vec<String> = frame
                    .fields
                    .iter()
                    .map(|field| {
                        serde_json::to_value(field)
                            .unwrap_or_default()
                            .as_str()
                            .unwrap_or("?")
                            .to_owned()
                    })
                    .collect();
                println!(
                    "FRAME {} {} {}",
                    frame.frame_id,
                    frame.origin,
                    fields.join(",")
                );
            }
            for item in &card.cards {
                println!("CARD {} {}", item.id, item.title);
            }
        }
        self.shown = now;
        let first = match &choices.card {
            Some(card) => card.cards.first().map(|item| (item.id.clone(), true)),
            None => choices
                .logins
                .first()
                .map(|login| (login.id.clone(), false)),
        };
        match (self.decide, choices.session) {
            (Decide::Deny, _) => self.deny(desk),
            (Decide::First, Some(_)) => match first {
                Some((item, card)) => self.approve(desk, &choices, &item, card),
                None => self.deny(desk),
            },
            _ => {}
        }
        Ok(())
    }

    fn command(&mut self, desk: &Arc<Desk>, line: &str) -> CliResult {
        match line.split_whitespace().collect::<Vec<_>>().as_slice() {
            [command @ ("approve" | "approve-card"), item] => {
                match desk.choices(Some(&self.vault))? {
                    // The choice is made under the unlock the request was last
                    // printed under, as the owner's would be.
                    Some(mut choices) => {
                        choices.session = self.shown.as_ref().and_then(|(_, session)| *session);
                        self.approve(desk, &choices, item, *command == "approve-card");
                    }
                    None => println!("REFUSED not-pending"),
                }
            }
            ["deny"] => self.deny(desk),
            ["lock"] => {
                self.vault.lock();
                println!("LOCKED");
            }
            ["unlock"] => {
                self.vault.unlock(&password()?)?;
                println!("UNLOCKED");
            }
            [] => {}
            _ => println!("FAILED {line}: unknown command"),
        }
        Ok(())
    }

    fn approve(&mut self, desk: &Arc<Desk>, choices: &Choices, item: &str, card: bool) {
        let request = &choices.request_id;
        let outcome = match choices.session {
            Some(session) if card => desk.approve_card(request, item, session, &self.vault),
            Some(session) => desk.approve(request, item, session, &self.vault),
            None => Err(Refused::Locked),
        };
        match outcome {
            Ok(()) => {
                self.shown = None;
                println!("FILLED {request} {item}");
            }
            Err(Refused::NotPending) => println!("REFUSED not-pending"),
            Err(Refused::Locked) => println!("REFUSED locked"),
            Err(Refused::NotForThisPage) => println!("REFUSED not-for-this-page"),
            Err(Refused::Vault(error)) => println!("REFUSED {error}"),
        }
    }

    fn deny(&mut self, desk: &Arc<Desk>) {
        match self.shown.take() {
            Some((request, _)) if desk.deny(&request) => println!("DENIED {request}"),
            _ => println!("REFUSED not-pending"),
        }
    }
}
