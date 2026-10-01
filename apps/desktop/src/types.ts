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
  state: "unpaired" | "idle" | "syncing" | "synced" | "received" | "error";
  lastSyncedAt?: number;
  message?: string;
  /** Short ID of the paired device. */
  peer?: string;
  peerAddress?: string;
  /** Revisions received while locked, verified at the next unlock. */
  pending: number;
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
  startInvite: () => Promise<{ code: string; expiresAt: number }>;
  confirmInvite: (accept: boolean) => Promise<void>;
  cancelInvite: () => Promise<void>;
  joinStart: (code: string) => Promise<{ sas: string }>;
  joinFinish: (password: string) => Promise<void>;
  cancelJoin: () => Promise<void>;
  /** Subscribes to a shell event; resolves to an unsubscribe function. */
  listen: <T>(event: string, handler: (payload: T) => void) => Promise<() => void>;
};
