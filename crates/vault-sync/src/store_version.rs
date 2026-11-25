//! The layout version of a device-local SQLite store, kept in SQLite's
//! `user_version`, so that a build can tell a store a later build wrote
//! from one it knows.

use rusqlite::Connection;

use crate::{Error, Result};

/// Checks that the store behind `connection` is no newer than layout
/// `current` and returns the stored version without modifying the file: 0 for
/// a new store and for one from before stores were marked.
pub fn check_store_version(connection: &Connection, current: u32) -> Result<u32> {
    let found: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found > current {
        return Err(Error::UnsupportedVersion);
    }
    Ok(found)
}

/// Writes `PRAGMA user_version = current` on `connection` (call inside the
/// migration transaction so a crash before commit never leaves the layout
/// version ahead of the schema).
pub fn set_store_version(connection: &Connection, current: u32) -> Result<()> {
    connection.pragma_update(None, "user_version", current)?;
    Ok(())
}

/// Marks the store behind `connection` as layout `current` and returns the
/// version it had: 0 for a new store and for one from before stores were
/// marked, which is layout 1. A store marked with a later version is
/// refused. Call this before anything else is done to the file, so that a
/// refused store is left as it is.
pub fn claim_store_version(connection: &Connection, current: u32) -> Result<u32> {
    let found = check_store_version(connection, current)?;
    if found < current {
        set_store_version(connection, current)?;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_is_marked_once_and_a_later_layout_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.sqlite3");
        let connection = Connection::open(&path).unwrap();
        assert_eq!(claim_store_version(&connection, 1).unwrap(), 0);
        assert_eq!(claim_store_version(&connection, 1).unwrap(), 1);
        drop(connection);

        // A later build's store is refused and not written to.
        let connection = Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
        drop(connection);
        let before = std::fs::read(&path).unwrap();
        let connection = Connection::open(&path).unwrap();
        assert!(matches!(
            claim_store_version(&connection, 1),
            Err(Error::UnsupportedVersion)
        ));
        drop(connection);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
