import type { ArchiveInfo, BrowserStatus, DesktopBridge, DevicesInfo, EntryDetail, EntryInput, FillAsked, HeldChange, SyncStatus, VaultEntry, VersionSummary } from "./types";

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

let previewEntries: VaultEntry[] = [
  { id: "1", title: "Proton Mail", kind: "login", username: "hello@northstar.dev", url: "proton.me", updatedAt: "Today, 09:42", favorite: true },
  { id: "2", title: "GitHub", kind: "login", username: "northstar-labs", url: "github.com", updatedAt: "Yesterday, 18:10", favorite: true },
  { id: "3", title: "Banking — checking", kind: "login", username: "•••• 4821", url: "secure.bank.example", updatedAt: "Sep 18", favorite: false },
  { id: "4", title: "Recovery codes", kind: "secure_note", updatedAt: "Sep 12", favorite: false },
  { id: "5", title: "Studio Wi-Fi", kind: "login", username: "studio", url: "network", updatedAt: "Aug 27", favorite: false },
];

const previewDetails = new Map<string, EntryDetail>();

function previewDetail(entry: VaultEntry): EntryDetail {
  return previewDetails.get(entry.id) ?? { id: entry.id, title: entry.title, kind: entry.kind, username: entry.username ?? "", url: entry.url ?? "", notes: "", favorite: Boolean(entry.favorite), hasPassword: entry.kind === "login", hasTotp: false, revision: entry.revision ?? "preview" };
}

/** Preview writes stay in memory and never retain the password or TOTP secret. */
function savePreview(id: string, input: EntryInput, previous?: EntryDetail): VaultEntry {
  const revision = crypto.randomUUID();
  const detail: EntryDetail = {
    id, title: input.title, kind: input.kind, username: input.username, url: input.url, notes: input.notes, favorite: input.favorite,
    hasPassword: input.password !== undefined ? input.password.length > 0 : Boolean(previous?.hasPassword),
    hasTotp: input.totpSecret !== undefined ? input.totpSecret.trim().length > 0 : Boolean(previous?.hasTotp),
    revision,
  };
  previewDetails.set(id, detail);
  const entry: VaultEntry = { id, title: input.title, kind: input.kind, username: input.username || undefined, url: input.url || undefined, updatedAt: "Just now", favorite: input.favorite, revision };
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
    return previewEntries;
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
    if (!previewEntries.some((existing) => existing.id === id)) throw new Error("not_found");
    previewEntries = previewEntries.filter((existing) => existing.id !== id);
    previewDetails.delete(id);
  },
  // Conflicts only arise from revisions received from another device, so
  // the browser preview has none to review.
  async listVersions(id) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return (await invoke("list_versions", { id })) as VersionSummary[];
    throw new Error("preview");
  },
  // Held changes come from other devices too; the preview has none.
  async listHeld() {
    const invoke = native();
    return invoke ? ((await invoke("list_held")) as HeldChange[]) : [];
  },
  acceptHeld: (revision) => nativeOnly("accept_held", { revision }),
  discardHeld: (revision) => nativeOnly("discard_held", { revision }),
  async syncStatus() {
    const invoke = native();
    if (invoke) return (await invoke("sync_status")) as SyncStatus;
    return { state: "local", devices: 0, pending: 0, replaced: [] };
  },
  async devices() {
    const invoke = native();
    if (invoke) return (await invoke("devices")) as DevicesInfo;
    return { setup: "none", members: [], epoch: 0, quorum: 0 };
  },
  foundControlPlane: () => nativeOnly("found_control_plane"),
  removeDevice: (device) => nativeOnly("remove_device", { device }),
  cancelEnrollment: () => nativeOnly("cancel_enrollment"),
  recoverVault: (password) => nativeOnly("recover_vault", { password }),
  async vaultProblem() {
    const invoke = native();
    return invoke ? ((await invoke("vault_problem")) as string | null) : null;
  },
  putUnreadableAway: () => nativeOnly("put_unreadable_away"),
  saveBackup: () => nativeOnly("save_backup"),
  chooseBackup: () => nativeOnly("choose_backup"),
  restoreBackup: (recoveryKey, password) => nativeOnly("restore_backup", { recoveryKey, password }),
  resetPassword: (recoveryKey, newPassword) => nativeOnly("reset_password", { recoveryKey, newPassword }),
  resetDevice: () => nativeOnly("reset_device"),
  leaveVault: (password) => nativeOnly("leave_vault", { password }),
  async recoveryStatus() {
    const invoke = native();
    return invoke ? Boolean(await invoke("recovery_status")) : true;
  },
  async pendingRecoveryKey() {
    const invoke = native();
    return invoke ? ((await invoke("pending_recovery_key")) as string | null) : null;
  },
  async confirmRecoveryKey() {
    const invoke = native();
    if (invoke) await invoke("confirm_recovery_key");
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
  startInvite: (votes) => nativeOnly("start_invite", { votes }),
  confirmInvite: (accept) => nativeOnly("confirm_invite", { accept }),
  cancelInvite: () => nativeOnly("cancel_invite"),
  joinStart: (code) => nativeOnly("join_start", { code }),
  joinFinish: (password) => nativeOnly("join_finish", { password: password ?? null }),
  cancelJoin: () => nativeOnly("cancel_join"),
  async listen(event, handler) {
    const listen = (globalThis as TauriGlobal).__TAURI__?.event?.listen;
    if (!listen) return () => {};
    return listen(event, (message) => handler(message.payload as never));
  },
  async resolveEntry(id, keepRevision, heads) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) await invoke("resolve_entry", { id, keepRevision, heads });
    else throw new Error("preview");
  },
};
