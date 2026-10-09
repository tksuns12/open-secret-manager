import type { ArchiveInfo, BackupAge, BrowserStatus, DeletedEntry, DesktopBridge, DevicesInfo, EntryDetail, EntryInput, FillAsked, HeldChange, HistoryEntry, ImportSummary, Settings, SyncStatus, VaultEntry, VersionSummary } from "./types";

type Invoke = (cmd: string, args?: unknown) => Promise<unknown>;
type Listen = (event: string, handler: (event: { payload: unknown }) => void) => Promise<() => void>;
type TauriGlobal = { __TAURI__?: { core?: { invoke?: Invoke }; event?: { listen?: Listen } } };

function native(): Invoke | undefined {
  return (globalThis as TauriGlobal).__TAURI__?.core?.invoke;
}

/** Pairing and sync need the native shell; the browser preview has neither. */
async function nativeOnly<T>(cmd: string, args?: unknown): Promise<T> {
  const invoke = native();
  if (!invoke) throw new Error("preview");
  return (await invoke(cmd, args)) as T;
}

/**
 * Whether the preview's address asks for a state the browser preview
 * otherwise never has, so that it can be looked at and tested: as in
 * `/?rows-changed`, `/?recovery-key`, `/?held`, `/?conflict`, `/?devices`, or
 * `/?backup-due`.
 * Each shows sample data, no secret.
 */
function previewAsks(what: string): boolean {
  return new URLSearchParams(globalThis.location?.search).has(what);
}

/** Whether the preview shows a vault of two devices (`?devices`): this one, which votes, and a phone, which does not. */
export function previewHasDevices(): boolean {
  return !native() && previewAsks("devices");
}

const previewDevices: DevicesInfo = {
  setup: "ready",
  thisDevice: "a1b2c3d4e5f60718",
  // In the shell's order, by ID: this device is not first.
  members: [
    { id: "9f8e7d6c5b4a3921", thisDevice: false, leader: false, votes: false, address: "192.168.1.23:47820" },
    { id: "a1b2c3d4e5f60718", thisDevice: true, leader: true, votes: true },
  ],
  epoch: 1,
  quorum: 1,
};

let previewEntries: VaultEntry[] = ([
  { id: "1", title: "Proton Mail", kind: "login", username: "hello@northstar.dev", url: "proton.me", favorite: true },
  { id: "2", title: "GitHub", kind: "login", username: "northstar-labs", url: "github.com", favorite: true },
  { id: "3", title: "Banking — checking", kind: "login", username: "•••• 4821", url: "secure.bank.example", favorite: false },
  { id: "4", title: "Recovery codes", kind: "secure_note", favorite: false },
  { id: "5", title: "Studio Wi-Fi", kind: "login", username: "studio", url: "network", favorite: false },
] satisfies VaultEntry[]).map((entry) => (entry.id === "2" && previewAsks("conflict") ? { ...entry, conflict: true } : entry));

/** With `?conflict`: the two versions of GitHub that were changed independently. */
const previewConflict: VersionSummary[] = [
  { revision: "preview-conflict-here", deleted: false, title: "GitHub", username: "northstar-labs", url: "github.com", device: "preview", thisDevice: true, differs: ["username", "password"] },
  { revision: "preview-conflict-there", deleted: false, title: "GitHub", username: "northstar-ops", url: "github.com", device: "3f9a1c2e", thisDevice: false, differs: ["username", "password"] },
];

/** With `?held`: changes written by a device that was removed, waiting for the owner. */
let previewHeld: HeldChange[] = previewAsks("held") ? [
  { revision: "preview-held-new", device: "7c41d09e", removedDevice: true, change: "new", title: "Old router", username: "admin", url: "192.168.0.1", changed: [] },
  { revision: "preview-held-edit", device: "7c41d09e", removedDevice: true, change: "edit", title: "Proton Mail", username: "hello@northstar.dev", url: "proton.me", changed: ["password"] },
] : [];

/** Whether the preview's owner confirmed storing the sample recovery key `?recovery-key` shows. */
let previewRecoveryConfirmed = false;

/** What the preview's import would add: sample data, no secret. */
const previewImport: ImportSummary = { file: "sample-export.csv", items: 2, logins: 2, notes: 0, cards: 0, identities: 0, already: 1, warnings: [{ row: 4, message: "entry has no password" }] };
let previewImportChosen = false;
let previewSettings: Settings = { autoLockMinutes: 5 };
/** Whether the preview's owner confirmed its warning that records were taken out of the file. */
let previewRowsConfirmed = false;

const previewDetails = new Map<string, EntryDetail>();
/** Items deleted in the preview, which it can bring back. */
let previewDeleted: VaultEntry[] = [];
/** The versions the preview's own edits made, newest first, with what each held: sample data, no secret. */
const previewHistory = new Map<string, { version: HistoryEntry; entry: VaultEntry }[]>();

function previewVersions(entry: VaultEntry): { version: HistoryEntry; entry: VaultEntry }[] {
  return previewHistory.get(entry.id) ?? [{ version: { revision: entry.revision ?? "preview", deleted: false, current: true, first: true, merged: false, title: entry.title, username: entry.username ?? "", url: entry.url ?? "", changed: [], device: "preview", thisDevice: true }, entry }];
}

/** Records the version an edit in the preview made, with the fields it changed. */
function recordPreviewVersion(entry: VaultEntry, input: EntryInput, previous?: EntryDetail) {
  const before = previewEntries.find((existing) => existing.id === entry.id);
  const versions = before ? previewVersions(before) : [];
  const changed = previous ? [
    previous.title !== input.title ? "title" : "",
    previous.username !== input.username ? "username" : "",
    input.password !== undefined ? "password" : "",
    previous.url !== input.url ? "website" : "",
    previous.notes !== input.notes ? "notes" : "",
  ].filter(Boolean) : [];
  const version: HistoryEntry = { revision: entry.revision ?? crypto.randomUUID(), deleted: false, current: true, first: !previous, merged: false, title: entry.title, username: entry.username ?? "", url: entry.url ?? "", changed, device: "preview", thisDevice: true };
  previewHistory.set(entry.id, [{ version, entry }, ...versions.map((older) => ({ ...older, version: { ...older.version, current: false } }))]);
}

function previewDetail(entry: VaultEntry): EntryDetail {
  return previewDetails.get(entry.id) ?? { id: entry.id, title: entry.title, kind: entry.kind, username: entry.username ?? "", url: entry.url ?? "", notes: "", favorite: Boolean(entry.favorite), hasPassword: entry.kind === "login", hasTotp: false, fields: [], revision: entry.revision ?? "preview" };
}

/** Preview writes stay in memory and never retain the password or TOTP secret. */
function savePreview(id: string, input: EntryInput, previous?: EntryDetail): VaultEntry {
  const revision = crypto.randomUUID();
  const detail: EntryDetail = {
    id, title: input.title, kind: input.kind, username: input.username, url: input.url, notes: input.notes, favorite: input.favorite,
    hasPassword: input.password !== undefined ? input.password.length > 0 : Boolean(previous?.hasPassword),
    hasTotp: input.totpSecret !== undefined ? input.totpSecret.trim().length > 0 : Boolean(previous?.hasTotp),
    fields: previous?.fields ?? [],
    revision,
  };
  previewDetails.set(id, detail);
  const entry: VaultEntry = { id, title: input.title, kind: input.kind, username: input.username || undefined, url: input.url || undefined, favorite: input.favorite, revision };
  recordPreviewVersion(entry, input, previous);
  previewEntries = [entry, ...previewEntries.filter((existing) => existing.id !== id)];
  return entry;
}

export function hasNativeBridge(): boolean {
  return Boolean((globalThis as { __TAURI__?: { core?: { invoke?: unknown } } }).__TAURI__?.core?.invoke);
}

/**
 * The preview keeps the interface useful in a browser. Tauri injects the
 * command bridge in production; no secret is placed in this fallback data.
 */
export const bridge: DesktopBridge = {
  async status() {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return String(await invoke("vault_status")) as "missing" | "locked" | "unlocked";
    return "unlocked";
  },
  async listEntries() {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return (await invoke("list_entries")) as VaultEntry[];
    // A new list each time, as the shell's is: the window reloads what goes
    // with the items when the list changes.
    return [...previewEntries];
  },
  async lock() {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) await invoke("lock_vault");
  },
  async unlock(password) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) await invoke("unlock_vault", { password });
  },
  async createVault(password) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return String(await invoke("create_vault", { password }));
    return "";
  },
  async generatePassword(length) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return String(await invoke("generate_password", { length }));
    const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%";
    const values = new Uint32Array(length);
    crypto.getRandomValues(values);
    return Array.from(values, (value) => alphabet[value % alphabet.length]).join("");
  },
  async copyTotp(id) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) await invoke("copy_totp", { id });
  },
  copyPassword: (id) => nativeOnly("copy_password", { id }),
  copyField: (id, name) => nativeOnly("copy_field", { id, name }),
  async getEntry(id) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return (await invoke("get_entry", { id })) as EntryDetail;
    const entry = previewEntries.find((existing) => existing.id === id);
    if (!entry) throw new Error("not_found");
    return previewDetail(entry);
  },
  async createEntry(input) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return (await invoke("create_entry", { input })) as VaultEntry;
    return savePreview(crypto.randomUUID(), input);
  },
  async updateEntry(id, expectedRevision, input) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return (await invoke("update_entry", { id, expectedRevision, input })) as VaultEntry;
    const entry = previewEntries.find((existing) => existing.id === id);
    if (!entry) throw new Error("not_found");
    return savePreview(id, input, previewDetail(entry));
  },
  async deleteEntry(id, expectedRevision) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) { await invoke("delete_entry", { id, expectedRevision }); return; }
    const gone = previewEntries.find((existing) => existing.id === id);
    if (!gone) throw new Error("not_found");
    previewEntries = previewEntries.filter((existing) => existing.id !== id);
    previewDeleted = [gone, ...previewDeleted];
  },
  // Conflicts only arise from revisions received from another device, so
  // the browser preview has one only when its address asks (`?conflict`).
  async listVersions(id) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return (await invoke("list_versions", { id })) as VersionSummary[];
    if (previewEntries.find((entry) => entry.id === id)?.conflict) return previewConflict;
    throw new Error("preview");
  },
  // Held changes come from other devices too; the preview has them only
  // when its address asks (`?held`).
  async listHeld() {
    const invoke = native();
    return invoke ? ((await invoke("list_held")) as HeldChange[]) : previewHeld;
  },
  async acceptHeld(revision) {
    const invoke = native();
    if (invoke) { await invoke("accept_held", { revision }); return; }
    const change = previewHeld.find((held) => held.revision === revision);
    if (!change) throw Object.assign(new Error("not_found"), { code: "not_found" });
    previewHeld = previewHeld.filter((held) => held !== change);
    if (change.change === "new") previewEntries = [...previewEntries, { id: crypto.randomUUID(), title: change.title, kind: "login", username: change.username, url: change.url, favorite: false }];
  },
  async discardHeld(revision) {
    const invoke = native();
    if (invoke) { await invoke("discard_held", { revision }); return; }
    if (!previewHeld.some((held) => held.revision === revision)) throw Object.assign(new Error("not_found"), { code: "not_found" });
    previewHeld = previewHeld.filter((held) => held.revision !== revision);
  },
  async syncStatus() {
    const invoke = native();
    if (invoke) return (await invoke("sync_status")) as SyncStatus;
    return previewHasDevices() ? { state: "idle", devices: 1, pending: 0, replaced: [] } : { state: "local", devices: 0, pending: 0, replaced: [] };
  },
  async devices() {
    const invoke = native();
    if (invoke) return (await invoke("devices")) as DevicesInfo;
    return previewHasDevices() ? previewDevices : { setup: "none", members: [], epoch: 0, quorum: 0 };
  },
  foundControlPlane: () => nativeOnly("found_control_plane"),
  removeDevice: (device) => nativeOnly("remove_device", { device }),
  cancelEnrollment: () => nativeOnly("cancel_enrollment"),
  recoverVault: (password) => nativeOnly("recover_vault", { password }),
  async startupProblem() {
    const invoke = native();
    return invoke ? ((await invoke("startup_problem")) as string | null) : null;
  },
  async vaultProblem() {
    const invoke = native();
    return invoke ? ((await invoke("vault_problem")) as string | null) : null;
  },
  putUnreadableAway: () => nativeOnly("put_unreadable_away"),
  saveBackup: () => nativeOnly("save_backup"),
  /** The preview's last backup was 45 days ago with `?backup-due`, and is recent otherwise. */
  async backupAge() {
    const invoke = native();
    if (invoke) return (await invoke("backup_age")) as BackupAge;
    return previewAsks("backup-due") ? { days: 45, due: true } : { days: 2, due: false };
  },
  chooseBackup: () => nativeOnly("choose_backup"),
  restoreBackup: (recoveryKey, password) => nativeOnly("restore_backup", { recoveryKey, password }),
  resetPassword: (recoveryKey, newPassword) => nativeOnly("reset_password", { recoveryKey, newPassword }),
  resetDevice: () => nativeOnly("reset_device"),
  leaveVault: (password) => nativeOnly("leave_vault", { password }),
  async recoveryStatus() {
    const invoke = native();
    return invoke ? Boolean(await invoke("recovery_status")) : true;
  },
  /** The preview shows a sample, until confirmed, with `?recovery-key`: not a key of any vault. */
  async pendingRecoveryKey() {
    const invoke = native();
    if (invoke) return (await invoke("pending_recovery_key")) as string | null;
    return previewAsks("recovery-key") && !previewRecoveryConfirmed ? "OSM-RK1-PREVIEW-SAMPLE-NOT-A-REAL-KEY" : null;
  },
  async confirmRecoveryKey() {
    const invoke = native();
    if (invoke) await invoke("confirm_recovery_key");
    else previewRecoveryConfirmed = true;
  },
  /** The preview says so, until confirmed, with `?rows-changed`. */
  async rowsChanged() {
    const invoke = native();
    return invoke ? Boolean(await invoke("rows_changed")) : !previewRowsConfirmed && previewAsks("rows-changed");
  },
  async confirmRowsChanged() {
    const invoke = native();
    if (invoke) await invoke("confirm_rows_changed");
    else previewRowsConfirmed = true;
  },
  enableRecovery: (recoveryKey) => nativeOnly("enable_recovery", { recoveryKey }),
  syncNow: () => nativeOnly("sync_now"),
  async listArchives() {
    const invoke = native();
    return invoke ? ((await invoke("list_archives")) as ArchiveInfo[]) : [];
  },
  openArchive: (name, password) => nativeOnly("open_archive", { name, password }),
  copyFromArchive: (id) => nativeOnly("copy_from_archive", { id }),
  async closeArchive() {
    const invoke = native();
    if (invoke) await invoke("close_archive");
  },
  deleteArchive: (name) => nativeOnly("delete_archive", { name }),
  // Requests come from a browser through the native shell; the preview
  // never has one.
  async fillRequest() {
    const invoke = native();
    return invoke ? ((await invoke("fill_request")) as FillAsked | null) : null;
  },
  approveFill: (requestId, itemId, session) => nativeOnly("approve_fill", { requestId, itemId, session }),
  denyFill: (requestId) => nativeOnly("deny_fill", { requestId }),
  async browserStatus() {
    const invoke = native();
    if (invoke) return (await invoke("browser_status")) as BrowserStatus;
    return { supported: false, listening: false, problem: null, host: null, temporaryPlace: false, browsers: [] };
  },
  connectBrowser: (browser) => nativeOnly("connect_browser", { browser }),
  disconnectBrowser: (browser) => nativeOnly("disconnect_browser", { browser }),
  /** With `?devices`, a sample invitation that pairs nothing. */
  async startInvite(votes) {
    if (native() || !previewHasDevices()) return nativeOnly("start_invite", { votes });
    return { code: "OSM-PAIR1-PREVIEW-SAMPLE-NOT-AN-INVITATION", expiresAt: Date.now() + 15 * 60_000 };
  },
  confirmInvite: (accept) => nativeOnly("confirm_invite", { accept }),
  async cancelInvite() {
    if (native() || !previewHasDevices()) await nativeOnly("cancel_invite");
  },
  joinStart: (code) => nativeOnly("join_start", { code }),
  joinFinish: (password) => nativeOnly("join_finish", { password: password ?? null }),
  cancelJoin: () => nativeOnly("cancel_join"),
  // The preview keeps no history but the item as it is now.
  async itemHistory(id) {
    const invoke = native();
    if (invoke) return (await invoke("item_history", { id })) as HistoryEntry[];
    const entry = previewEntries.find((existing) => existing.id === id);
    if (!entry) throw new Error("not_found");
    return previewVersions(entry).map((saved) => saved.version);
  },
  async deletedEntries() {
    const invoke = native();
    if (invoke) return (await invoke("deleted_entries")) as DeletedEntry[];
    return previewDeleted.map((entry) => ({ id: entry.id, title: entry.title, kind: entry.kind, username: entry.username ?? "", url: entry.url ?? "", last: entry.revision ?? "preview", heads: ["preview-deletion"], device: "preview", thisDevice: true }));
  },
  async restoreEntry(id, revision, heads) {
    const invoke = native();
    if (invoke) return (await invoke("restore_entry", { id, revision, heads })) as VaultEntry;
    const deleted = previewDeleted.find((gone) => gone.id === id);
    const current = deleted ?? previewEntries.find((existing) => existing.id === id);
    if (!current) throw new Error("not_found");
    const earlier = previewVersions(current).find((saved) => saved.version.revision === revision);
    const restored = deleted ?? { ...(earlier?.entry ?? current), revision: crypto.randomUUID() };
    if (!deleted && earlier) {
      const versions = previewVersions(current).map((saved) => ({ ...saved, version: { ...saved.version, current: false } }));
      const changed = [current.title !== restored.title ? "title" : "", current.username !== restored.username ? "username" : "", current.url !== restored.url ? "website" : ""].filter(Boolean);
      previewHistory.set(id, [{ version: { ...earlier.version, revision: restored.revision ?? "", current: true, first: false, changed }, entry: restored }, ...versions]);
      previewDetails.delete(id);
    }
    previewDeleted = previewDeleted.filter((gone) => gone.id !== id);
    previewEntries = [restored, ...previewEntries.filter((existing) => existing.id !== id)];
    return restored;
  },
  // The preview's import is sample data: no file is read.
  async chooseImport(format) {
    const invoke = native();
    if (invoke) return (await invoke("choose_import", { format })) as ImportSummary | null;
    previewImportChosen = true;
    return previewImport;
  },
  async confirmImport() {
    const invoke = native();
    if (invoke) return (await invoke("confirm_import")) as number;
    if (!previewImportChosen) throw new Error("no_import");
    previewImportChosen = false;
    previewEntries = [...previewEntries, { id: crypto.randomUUID(), title: "Sample import one", kind: "login", username: "sample", url: "one.example", favorite: false }, { id: crypto.randomUUID(), title: "Sample import two", kind: "login", username: "sample", url: "two.example", favorite: false }];
    return previewImport.items;
  },
  async cancelImport() {
    const invoke = native();
    if (invoke) await invoke("cancel_import");
    previewImportChosen = false;
  },
  async settings() {
    const invoke = native();
    return invoke ? ((await invoke("settings")) as Settings) : previewSettings;
  },
  async setAutoLock(minutes) {
    const invoke = native();
    if (invoke) return (await invoke("set_auto_lock", { minutes })) as Settings;
    previewSettings = { autoLockMinutes: minutes };
    return previewSettings;
  },
  async listen(event, handler) {
    const listen = (globalThis as TauriGlobal).__TAURI__?.event?.listen;
    if (!listen) return () => {};
    return listen(event, (message) => handler(message.payload as never));
  },
  async resolveEntry(id, keepRevision, heads) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) { await invoke("resolve_entry", { id, keepRevision, heads }); return; }
    const kept = previewConflict.find((version) => version.revision === keepRevision);
    const entry = previewEntries.find((existing) => existing.id === id);
    if (!kept || !entry?.conflict) throw new Error("preview");
    previewEntries = previewEntries.map((existing) => existing.id === id ? { ...existing, conflict: false, title: kept.title, username: kept.username, url: kept.url, revision: crypto.randomUUID() } : existing);
    previewDetails.delete(id);
  },
};
