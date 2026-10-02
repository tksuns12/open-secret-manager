export type EntryKind = "login" | "secure_note" | "identity";

export type VaultEntry = {
  id: string;
  title: string;
  kind: EntryKind;
  username?: string;
  url?: string;
  updatedAt: string;
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
  revision: string;
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
};

/** A membership change the vault's devices have accepted but not finished. */
export type PendingChange = {
  kind: "enroll" | "remove";
  device: string;
  cancelled: boolean;
};

/** The vault's devices as its committed membership records them. */
export type DevicesInfo = {
  setup: "none" | "unmanaged" | "paired-before" | "joining" | "ready" | "removed";
  thisDevice?: string;
  members: MemberInfo[];
  pending?: PendingChange;
  epoch: number;
  /** How many devices must be reachable for any change. */
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
  getEntry: (id: string) => Promise<EntryDetail>;
  createEntry: (input: EntryInput) => Promise<VaultEntry>;
  updateEntry: (id: string, expectedRevision: string, input: EntryInput) => Promise<VaultEntry>;
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
  enableRecovery: (recoveryKey: string) => Promise<void>;
  syncStatus: () => Promise<SyncStatus>;
  syncNow: () => Promise<void>;
  devices: () => Promise<DevicesInfo>;
  /** For a pair set up by an older build: makes this device the first member. */
  foundControlPlane: () => Promise<void>;
  removeDevice: (device: string) => Promise<void>;
  cancelEnrollment: () => Promise<void>;
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
  startInvite: () => Promise<{ code: string; expiresAt: number }>;
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
  /** Subscribes to a shell event; resolves to an unsubscribe function. */
  listen: <T>(event: string, handler: (payload: T) => void) => Promise<() => void>;
};
