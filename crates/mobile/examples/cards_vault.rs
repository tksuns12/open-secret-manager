//! A copy of a frozen vault with a card and an identity added, for the
//! phone apps' tests of an item's other fields: the frozen vaults hold
//! neither, and a phone cannot make them.
//!
//!   cargo run -p osm-mobile --example cards_vault -- <fixture folder> <copy>
//!
//! The fixture folder is one of `crates/vault-core/fixtures`; the copy opens
//! with that fixture's password.

use osm_vault_core::{Item, ItemKind, Vault};

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [fixture, copy] = arguments.as_slice() else {
        panic!("usage: cards_vault <fixture folder> <copy>");
    };
    let fixture = std::path::Path::new(fixture);
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("expected.json")).unwrap()).unwrap();
    let _ = std::fs::remove_file(copy);
    std::fs::copy(fixture.join("vault.sqlite3"), copy).unwrap();
    let mut vault = Vault::open(copy).unwrap();
    vault
        .unlock(expected["password"].as_str().unwrap())
        .unwrap();
    vault
        .put(item(
            "phone-card",
            "Visa",
            ItemKind::Card,
            &[
                ("Cardholder name", "Owner"),
                ("Number", "4111111111111111"),
                ("Expiry month", "12"),
                ("Expiry year", "2030"),
                ("Security code", "123"),
            ],
        ))
        .unwrap();
    vault
        .put(item(
            "phone-identity",
            "Passport",
            ItemKind::Identity,
            &[
                ("First name", "Ada"),
                ("Last name", "Owner"),
                ("Passport number", "X1234567"),
                ("Country", "Iceland"),
            ],
        ))
        .unwrap();
}

fn item(id: &str, title: &str, kind: ItemKind, fields: &[(&str, &str)]) -> Item {
    let mut item = Item::new(title);
    item.id = id.into();
    item.kind = kind;
    for (name, value) in fields {
        item.custom_fields.insert((*name).into(), (*value).into());
    }
    item
}
