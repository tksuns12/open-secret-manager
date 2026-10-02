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
  /** Set on a device without a vault that was removed from one: the folder its copy was moved to. */
  resetArchive?: string;
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
  recoveryStatus: () => Promise<boolean>;
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
  startInvite: () => Promise<{ code: string; expiresAt: number }>;
  confirmInvite: (accept: boolean) => Promise<void>;
  cancelInvite: () => Promise<void>;
  joinStart: (code: string) => Promise<{ sas: string; keepsVault: boolean }>;
  /** `password` is the new device password; omitted when this device keeps its vault. */
  joinFinish: (password?: string) => Promise<void>;
  cancelJoin: () => Promise<void>;
  /** Subscribes to a shell event; resolves to an unsubscribe function. */
  listen: <T>(event: string, handler: (payload: T) => void) => Promise<() => void>;
};
