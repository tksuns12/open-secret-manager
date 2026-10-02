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
        ["serve", vault, socket, options @ ..] => {
            let socket = match *socket {
                "-" => endpoint::socket_path().ok_or("this account has no data folder")?,
                path => PathBuf::from(path),
            };
            Owner::new(vault, options)?.serve(socket).await
        }
        _ => Err("usage: osm-fill create|add|serve ... (see the source header)".into()),
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
        println!(
            "REQUEST {} {} {} {}",
            choices.request_id,
            choices.origin,
            choices.browser,
            match choices.session {
                Some(_) => choices.logins.len().to_string(),
                None => "locked".into(),
            }
        );
        for login in &choices.logins {
            println!("LOGIN {} {}", login.id, login.title);
        }
        self.shown = now;
        match (self.decide, choices.session) {
            (Decide::Deny, _) => self.deny(desk),
            (Decide::First, Some(_)) => match choices.logins.first() {
                Some(login) => self.approve(desk, &choices, &login.id),
                None => self.deny(desk),
            },
            _ => {}
        }
        Ok(())
    }

    fn command(&mut self, desk: &Arc<Desk>, line: &str) -> CliResult {
        match line.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["approve", item] => match desk.choices(Some(&self.vault))? {
                // The choice is made under the unlock the request was last
                // printed under, as the owner's would be.
                Some(mut choices) => {
                    choices.session = self.shown.as_ref().and_then(|(_, session)| *session);
                    self.approve(desk, &choices, item);
                }
                None => println!("REFUSED not-pending"),
            },
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

    fn approve(&mut self, desk: &Arc<Desk>, choices: &Choices, item: &str) {
        let request = &choices.request_id;
        let outcome = match choices.session {
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
