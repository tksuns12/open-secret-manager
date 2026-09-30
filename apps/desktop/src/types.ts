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
};

export type SyncState = "connected" | "received" | "offline";

export type DesktopBridge = {
  status: () => Promise<"missing" | "locked" | "unlocked">;
  listEntries: () => Promise<VaultEntry[]>;
  unlock: (password: string) => Promise<void>;
  createVault: (password: string) => Promise<string>;
  lock: () => Promise<void>;
  generatePassword: (length: number) => Promise<string>;
  copyTotp: (id: string) => Promise<void>;
};
