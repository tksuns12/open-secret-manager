export type EntryKind = "login" | "secure_note" | "identity" | "card";

export type VaultEntry = {
  id: string;
  title: string;
  kind: EntryKind;
  username?: string;
  url?: string;
  favorite?: boolean;
  conflict?: boolean;
  revision?: string;
};

/** Editable fields; the stored password and TOTP secret are never returned. */
export type EntryDetail = {
  id: string;
  title: string;
  kind: EntryKind;
  username: string;
  url: string;
  notes: string;
  favorite: boolean;
  hasPassword: boolean;
  hasTotp: boolean;
  /** The names of the item's other fields, such as an imported card's number; their values are copied, never sent here. */
  fields: string[];
  revision: string;
};

/** One version of an item, as its history shows it. No secret. */
export type HistoryEntry = {
  revision: string;
  /** It deleted the item. */
  deleted: boolean;
  /** It is one of the item's current versions. */
  current: boolean;
  /** It made the item. */
  first: boolean;
  /** It settled a conflict between versions. */
  merged: boolean;
  title: string;
  username: string;
  url: string;
  /** The fields it changed from the version it followed. */
  changed: string[];
  device: string;
  thisDevice: boolean;
};

/** An item deleted on every device, as it was before. No secret. */
export type DeletedEntry = {
  id: string;
  title: string;
  kind: EntryKind;
  username: string;
  url: string;
  /** The version before the deletion, which a restore brings back. */
  last: string;
  /** The deletions, which a restore follows. */
  heads: string[];
  device: string;
  thisDevice: boolean;
};

/** The exports the app imports. */
export type ImportFormat = "bitwarden" | "chrome" | "firefox";

/** What an import would add, shown before the owner confirms. No secret. */
export type ImportSummary = {
  file: string;
  items: number;
  logins: number;
  notes: number;
  cards: number;
  identities: number;
  /** Items with the same kind, website, and username as one the vault has; added as items of their own all the same. */
  already: number;
  /** Entries of the file that were skipped, with why. */
  warnings: { row: number; message: string }[];
};

/** How long this device's vault has gone without a backup from this device. */
export type BackupAge = {
  /** Whole days since this device last saved a backup of its vault; `null` if it has not. */
  days: number | null;
  /** Whether to remind: 30 days or more since that backup, or since this device began counting without one. Never on a device without recovery, which cannot save one. */
  due: boolean;
};

/** What the owner sets on this device. */
export type Settings = {
  /** Minutes without activity before the window locks the vault: 1, 5, 15, or 60. */
  autoLockMinutes: number;
};

/** `password` and `totpSecret` are omitted to keep the stored value; an empty `totpSecret` removes it. */
export type EntryInput = {
  title: string;
  kind: EntryKind;
  username: string;
  url: string;
  notes: string;
  favorite: boolean;
  password?: string;
  totpSecret?: string;
};

/** One side of a conflict. Secrets are never included. */
export type VersionSummary = {
  revision: string;
  deleted: boolean;
  title: string;
  username: string;
  url: string;
  device: string;
  thisDevice: boolean;
  /** The fields in which this version differs from the others, by name only. */
  differs: string[];
};

/** A change held for review: written by a device that is not, or is no longer, one of the vault's devices. Secrets are never included. */
export type HeldChange = {
  revision: string;
  /** Short hex prefix of the author device ID. */
  device: string;
  /** The author was removed from the vault and the change verifies as its own; otherwise this device does not know who wrote it. */
  removedDevice: boolean;
  /** `restore` is an edit of an item that is deleted here. */
  change: "new" | "edit" | "delete" | "restore";
  /** The held version's fields, or for a deletion the item's as it is here now. */
  title: string;
  username: string;
  url: string;
  /** For an edit: which fields differ from the item as it is here now. */
  changed: string[];
};

/** A copy of a vault that was put away on this device, in a folder beside the vault. */
export type ArchiveInfo = {
  /** The folder's name; the other archive calls take it. */
  name: string;
  /** When it was put away, in seconds since the Unix epoch. */
  archivedAt: number;
  path: string;
  /** Whether the folder holds a vault file. */
  hasVault: boolean;
};

/** An item of an opened archived copy. Secrets are never included. */
export type ArchivedItem = {
  id: string;
  title: string;
  kind: EntryKind;
  username: string;
  url: string;
  /** The archived copy holds conflicting versions of this item. */
  conflict: boolean;
  /** How it relates to the vault here now; absent from the payload when there is no unlocked vault to compare with. */
  relation?: "same" | "differs" | "absent" | null;
  /** For `differs`: which fields differ. */
  changed: string[];
};

export type SyncState = "connected" | "received" | "offline";

/** Mirrors the desktop shell's sync status; secrets never appear here. */
export type SyncStatus = {
  /** `local` means there is no other device to sync with. */
  state: "local" | "idle" | "syncing" | "synced" | "received" | "error" | "removed";
  lastSyncedAt?: number;
  message?: string;
  /** How many other devices this one syncs with. */
  devices: number;
  /** Revisions received while locked, verified at the next unlock. */
  pending: number;
  /** Members, as hex device IDs, at whose address something answered as a different device. This device refuses that; it is what a device sees when another one started over as a new vault. */
  replaced: string[];
};

export type MemberInfo = {
  /** Device ID in hex. */
  id: string;
  thisDevice: boolean;
  address?: string;
  leader: boolean;
  /** Counts toward the majority a change needs. A member without a vote, such as a phone, holds the keys and syncs. */
  votes: boolean;
};

/** A membership change the vault's devices have accepted but not finished. */
export type PendingChange = {
  kind: "enroll" | "remove";
  device: string;
  /** Whether the device being enrolled or removed votes. */
  votes: boolean;
  cancelled: boolean;
};

/** The vault's devices as its committed membership records them. */
export type DevicesInfo = {
  setup: "none" | "unmanaged" | "paired-before" | "joining" | "ready" | "removed";
  thisDevice?: string;
  members: MemberInfo[];
  pending?: PendingChange;
  epoch: number;
  /** How many of the devices that vote must be reachable for any change. */
  quorum: number;
  /** Set on a device without a vault whose copy of one was put away: the folder it was moved to. */
  resetArchive?: string;
  /** Why: `removed` by the vault's devices, or `left` at the owner's request on this device. */
  resetReason?: "removed" | "left";
};

/** What starting over as a new vault produced. */
export type Recovered = {
  /** The new vault's recovery key, shown once. */
  recoveryKey: string;
  items: number;
  /** Items carried with more than one version, still to be resolved. */
  conflicts: number;
  /** Revisions that were held for review and stay in the old vault. */
  heldLeftBehind: number;
  /** Folder the old vault and its files were moved to. */
  archive: string;
};

/** A backup just saved, as read back from its file. */
export type SavedBackup = {
  path: string;
  /** Items in it, deleted ones included. */
  items: number;
  /** Versions of those items, kept as history. */
  revisions: number;
  /** Changes held for review. */
  held: number;
};

/** What restoring a backup as a new vault produced. */
export type Restored = {
  /** The new vault's recovery key, shown once. */
  recoveryKey: string;
  items: number;
  /** Items carried with more than one version, still to be resolved. */
  conflicts: number;
  /** Changes held for review in the backup, which stay in the copy restored as it was. */
  heldLeftBehind: number;
  /** Folder holding the backup restored as it was, with its history; the new password opens it from the Archive. */
  archive: string;
};

/** A login the owner may choose for a browser fill. Its password is never included. */
export type FillLogin = {
  id: string;
  title: string;
  username: string;
  url: string;
  /** The item has conflicting versions; the one the vault shows is sent. */
  conflict: boolean;
};

/** A login that is not offered although its address names the same host. */
export type FillNotOffered = {
  title: string;
  url: string;
  /** The address lacks `https://`, or is an `http://` address. */
  reason: "no_scheme" | "not_https";
};

/** A request from a browser extension that waits for the owner. */
export type FillAsked = {
  requestId: string;
  /** The origin of the page that would be filled. */
  origin: string;
  /** The kind of browser the request came from. */
  browser: string;
  secondsLeft: number;
  /** Names the unlock the logins were listed under; null while the vault is locked or missing. Handed back with the choice. */
  session: string | null;
  /** The logins stored for exactly that origin. */
  logins: FillLogin[];
  notOffered: FillNotOffered[];
};

export type BrowserInfo = {
  id: string;
  name: string;
  /** `other`: the browser is set up to start a program under this app's name that is not this app's. */
  state: "connected" | "not_connected" | "other";
  /** The file that tells the browser where the program is. */
  manifest: string;
  pointsTo: string | null;
};

export type BrowserStatus = {
  /** Whether this system can serve a browser at all. */
  supported: boolean;
  /** Whether the app is listening for the browser's requests. */
  listening: boolean;
  problem: string | null;
  /** The program a browser starts to reach this app, if it was found. */
  host: string | null;
  /** The app runs from a place that is gone when it quits, so no browser can be pointed at it. */
  temporaryPlace: boolean;
  /** The browsers found on this account. */
  browsers: BrowserInfo[];
};

export type DesktopBridge = {
  status: () => Promise<"missing" | "locked" | "unlocked">;
  listEntries: () => Promise<VaultEntry[]>;
  unlock: (password: string) => Promise<void>;
  createVault: (password: string) => Promise<string>;
  lock: () => Promise<void>;
  generatePassword: (length: number) => Promise<string>;
  copyTotp: (id: string) => Promise<void>;
  /** Copies an item's password for 30 seconds; the password never reaches the window. */
  copyPassword: (id: string) => Promise<void>;
  /** Copies the value of one of an item's other fields for 30 seconds. */
  copyField: (id: string, name: string) => Promise<void>;
  getEntry: (id: string) => Promise<EntryDetail>;
  createEntry: (input: EntryInput) => Promise<VaultEntry>;
  updateEntry: (id: string, expectedRevision: string, input: EntryInput) => Promise<VaultEntry>;
  deleteEntry: (id: string, expectedRevision: string) => Promise<void>;
  listVersions: (id: string) => Promise<VersionSummary[]>;
  resolveEntry: (id: string, keepRevision: string, heads: string[]) => Promise<void>;
  /** Changes held for the owner's review; needs the vault unlocked. */
  listHeld: () => Promise<HeldChange[]>;
  /** Keeps a held change as a change made by this device. */
  acceptHeld: (revision: string) => Promise<void>;
  /** Rejects a held change; the item stays as it is here. */
  discardHeld: (revision: string) => Promise<void>;
  recoveryStatus: () => Promise<boolean>;
  /** The recovery key of a vault made on this device that the owner has not confirmed storing; needs the vault unlocked. */
  pendingRecoveryKey: () => Promise<string | null>;
  /** The owner stored the recovery key; the vault stops keeping it. */
  confirmRecoveryKey: () => Promise<void>;
  /** Whether the last unlock found records taken out of the vault's file, which the owner has not yet confirmed seeing. */
  rowsChanged: () => Promise<boolean>;
  confirmRowsChanged: () => Promise<void>;
  enableRecovery: (recoveryKey: string) => Promise<void>;
  syncStatus: () => Promise<SyncStatus>;
  syncNow: () => Promise<void>;
  devices: () => Promise<DevicesInfo>;
  /** For a pair set up by an older build: makes this device the first member. */
  foundControlPlane: () => Promise<void>;
  removeDevice: (device: string) => Promise<void>;
  cancelEnrollment: () => Promise<void>;
  /** Why the app could not start on this computer's files, or `null` when it started; asked before anything else. */
  startupProblem: () => Promise<string | null>;
  /** Why the vault file on this device cannot be opened, or `null` if there is none or it opens. */
  vaultProblem: () => Promise<string | null>;
  /** Moves a vault file that cannot be opened to an archive folder; resolves to that folder. */
  putUnreadableAway: () => Promise<string>;
  /** Asks where to save a backup and saves it; `null` if the owner closed the dialog. */
  saveBackup: () => Promise<SavedBackup | null>;
  /** How long the unlocked vault has gone without a backup from this device. */
  backupAge: () => Promise<BackupAge>;
  /** Asks for a backup to restore; resolves to its file name, or `null`. The path stays with the shell. */
  chooseBackup: () => Promise<string | null>;
  /** Restores the chosen backup as a new vault on this device, which has none. */
  restoreBackup: (recoveryKey: string, password: string) => Promise<Restored>;
  /** For a forgotten password: unlocks with the recovery key and sets a new password on this device. */
  resetPassword: (recoveryKey: string, newPassword: string) => Promise<void>;
  /** Starts over from this device as a new vault; `password` is the vault password. */
  recoverVault: (password: string) => Promise<Recovered>;
  /** For a removed device: puts its copy in an archive folder so it can join again. Resolves to that folder. */
  resetDevice: () => Promise<string>;
  /** For a device whose vault was replaced by a new one started on another device: puts its copy in an archive folder so it can join that one. `password` is this device's. Resolves to the folder. */
  leaveVault: (password: string) => Promise<string>;
  /** Copies of a vault put away on this device, newest first. */
  listArchives: () => Promise<ArchiveInfo[]>;
  /** Opens one with the password it had; resolves to its items. It stays open until closed or the vault locks. */
  openArchive: (name: string, password: string) => Promise<ArchivedItem[]>;
  /** Copies an item of the opened copy into the vault as a new item; resolves to the copy's items again. */
  copyFromArchive: (id: string) => Promise<ArchivedItem[]>;
  closeArchive: () => Promise<void>;
  /** Deletes the folder and everything in it. */
  deleteArchive: (name: string) => Promise<void>;
  /** Invites a device; `votes` says whether it will count toward the majority a change needs. */
  startInvite: (votes: boolean) => Promise<{ code: string; expiresAt: number }>;
  confirmInvite: (accept: boolean) => Promise<void>;
  cancelInvite: () => Promise<void>;
  joinStart: (code: string) => Promise<{ sas: string; keepsVault: boolean }>;
  /** `password` is the new device password; omitted when this device keeps its vault. */
  joinFinish: (password?: string) => Promise<void>;
  cancelJoin: () => Promise<void>;
  /** The request from a browser that waits for the owner, if any. */
  fillRequest: () => Promise<FillAsked | null>;
  /** Sends the chosen login's user name and password to the page that asked. `session` is the one the request was shown with. */
  approveFill: (requestId: string, itemId: string, session: string) => Promise<void>;
  denyFill: (requestId: string) => Promise<void>;
  browserStatus: () => Promise<BrowserStatus>;
  /** Tells a browser where to find this app; resolves to the new status. */
  connectBrowser: (browser: string) => Promise<BrowserStatus>;
  disconnectBrowser: (browser: string) => Promise<BrowserStatus>;
  /** Every version of an item, newest first. */
  itemHistory: (id: string) => Promise<HistoryEntry[]>;
  /** The items deleted, most recently first. */
  deletedEntries: () => Promise<DeletedEntry[]>;
  /** Brings back what version `revision` of an item held, following its current versions `heads`; resolves to the item. */
  restoreEntry: (id: string, revision: string, heads: string[]) => Promise<VaultEntry>;
  /** Asks for an export of `format` and reads it; resolves to what it would add, or `null` if the owner closed the dialog. The file stays with the shell. */
  chooseImport: (format: ImportFormat) => Promise<ImportSummary | null>;
  /** Adds what the chosen export holds as new items; resolves to how many. */
  confirmImport: () => Promise<number>;
  /** Drops the export read for an import not confirmed. */
  cancelImport: () => Promise<void>;
  settings: () => Promise<Settings>;
  setAutoLock: (minutes: number) => Promise<Settings>;
  /** Subscribes to a shell event; resolves to an unsubscribe function. */
  listen: <T>(event: string, handler: (payload: T) => void) => Promise<() => void>;
};
