//! An invitation drawn as a QR code, for a phone to scan instead of the
//! owner pasting it. The code holds the invitation's text itself, so a phone
//! reads exactly what it would have been given pasted, and checks it the
//! same way; like the text, it proves nothing about who shows it (the codes
//! the owner compares do).

use qrcodegen::{QrCode, QrCodeEcc};
use serde::Serialize;

use crate::CommandError;

/// The light border a scanner needs around the code, in modules.
const QUIET_ZONE: i32 = 4;

/// A QR code for the window to draw: the side of its square in modules,
/// the light border included, and SVG path data that fills the dark ones.
#[derive(Debug, Serialize)]
pub struct QrInfo {
    pub(crate) side: u32,
    pub(crate) path: String,
}

/// The QR code of `text`, at error correction level M, which survives a
/// smudge or glare on a screen yet keeps an invitation of four addresses
/// within 85 modules a side.
pub fn qr_of(text: &str) -> Result<QrInfo, CommandError> {
    let code = QrCode::encode_text(text, QrCodeEcc::Medium).map_err(|_| CommandError {
        code: "invitation_too_long",
        message: "the invitation is too long for a QR code".into(),
    })?;
    Ok(QrInfo {
        side: (code.size() + 2 * QUIET_ZONE) as u32,
        path: path_of(&code),
    })
}

/// SVG path data with one rectangle for each run of dark modules in a row,
/// placed inside the quiet zone.
fn path_of(code: &QrCode) -> String {
    let mut path = String::new();
    for y in 0..code.size() {
        let mut x = 0;
        while x < code.size() {
            if !code.get_module(x, y) {
                x += 1;
                continue;
            }
            let start = x;
            while x < code.size() && code.get_module(x, y) {
                x += 1;
            }
            let run = x - start;
            path.push_str(&format!(
                "M{} {}h{run}v1h-{run}z",
                start + QUIET_ZONE,
                y + QUIET_ZONE
            ));
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// The squares `path` fills, as rows of `#` for dark and `.` for light.
    fn grid_of(qr: &QrInfo) -> Vec<String> {
        let side = qr.side as usize;
        let mut grid = vec![vec!['.'; side]; side];
        for rectangle in qr.path.split_terminator('z') {
            let (start, rest) = rectangle
                .strip_prefix('M')
                .unwrap()
                .split_once('h')
                .unwrap();
            let (x, y) = start.split_once(' ').unwrap();
            let (x, y): (usize, usize) = (x.parse().unwrap(), y.parse().unwrap());
            let (run, back) = rest.split_once("v1h-").unwrap();
            assert_eq!(run, back);
            for cell in &mut grid[y][x..x + run.parse::<usize>().unwrap()] {
                *cell = '#';
            }
        }
        grid.into_iter().map(String::from_iter).collect()
    }

    fn fixture_invitation() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../crates/vault-peer/fixtures/pairing.json");
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        fixture["invitation_text"].as_str().unwrap().to_owned()
    }

    #[test]
    fn the_path_fills_the_dark_modules_and_nothing_else() {
        let text = fixture_invitation();
        let code = QrCode::encode_text(&text, QrCodeEcc::Medium).unwrap();
        let qr = qr_of(&text).unwrap();
        assert_eq!(qr.side as i32, code.size() + 8);
        let grid = grid_of(&qr);
        for (y, row) in grid.iter().enumerate() {
            for (x, cell) in row.chars().enumerate() {
                let (x, y) = (x as i32 - QUIET_ZONE, y as i32 - QUIET_ZONE);
                assert_eq!(cell == '#', code.get_module(x, y), "at {x}, {y}");
            }
        }
    }

    #[test]
    fn an_invitation_of_up_to_four_addresses_stays_within_85_modules_a_side() {
        // 261 characters is the frozen invitation with two addresses; 377
        // one with two IPv4 and two IPv6 ones; 469 four of the longest IPv6.
        for length in [261, 377, 469] {
            let text = format!("OSM-PAIR1-{}", "Ab9_-".repeat(100))[..length].to_owned();
            let side = qr_of(&text).unwrap().side - 8;
            assert!((65..=85).contains(&side), "{length} characters: {side}");
        }
        assert!(qr_of(&"x".repeat(3000)).is_err());
    }

    /// The QR code of the frozen invitation, which the phones' tests read
    /// back: a change to how the window draws it shows here.
    #[test]
    fn the_frozen_invitation_draws_the_frozen_code() {
        let made = grid_of(&qr_of(&fixture_invitation()).unwrap()).join("\n") + "\n";
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/invitation-qr.txt");
        // A frozen file is not written over. To make it again, remove it and
        // run once with `OSM_WRITE_NEW_FIXTURES=1`.
        if !path.exists() && std::env::var_os("OSM_WRITE_NEW_FIXTURES").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &made).unwrap();
        }
        assert_eq!(made, std::fs::read_to_string(&path).unwrap());
    }
}
