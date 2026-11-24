import { cardBrand, cardDigits } from "./card";
import type { ArchiveInfo, BackupAge, BrowserStatus, CardDetail, DeletedEntry, DesktopBridge, DevicesInfo, EntryDetail, EntryInput, FillAsked, GeneratorChoice, HeldChange, HistoryEntry, ImportSummary, PasskeySummary, PasswordHealth, Settings, SyncStatus, VaultEntry, VersionSummary } from "./types";

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
 * `/?rows-changed`, `/?recovery-key`, `/?held`, `/?conflict`, `/?devices`,
 * `/?many`, or `/?backup-due` (or `/?no-backup`).
 * Each shows sample data, no secret.
 */
function previewAsks(what: string): boolean {
  return new URLSearchParams(globalThis.location?.search).has(what);
}

/** Whether the preview shows a vault of two devices (`?devices`): this one, which votes, and a phone, which does not. With `?without-vote` as well, this one is the device that does not vote, and the other the only one that does. */
export function previewHasDevices(): boolean {
  return !native() && previewAsks("devices");
}

const previewDevices: DevicesInfo = {
  setup: "ready",
  thisDevice: "a1b2c3d4e5f60718",
  // In the shell's order, by ID: this device is not first.
  members: [
    { id: "9f8e7d6c5b4a3921", thisDevice: false, leader: false, votes: false, address: "192.168.1.23:47820", addresses: ["192.168.1.23:47820", "100.101.102.103:47820"] },
    { id: "a1b2c3d4e5f60718", thisDevice: true, leader: true, votes: true, addresses: ["192.168.1.10:47820", "100.101.102.104:47820"] },
  ],
  epoch: 1,
  quorum: 1,
};

let previewRelay: DevicesInfo["relay"] = null;

let previewEntries: VaultEntry[] = ([
  { id: "1", title: "Proton Mail", kind: "login", username: "hello@northstar.dev", url: "proton.me", favorite: true },
  { id: "2", title: "GitHub", kind: "login", username: "northstar-labs", url: "github.com", favorite: true, passkeys: 1 },
  { id: "3", title: "Banking — checking", kind: "login", username: "•••• 4821", url: "secure.bank.example", favorite: false },
  { id: "4", title: "Recovery codes", kind: "secure_note", favorite: false },
  { id: "5", title: "Studio Wi-Fi", kind: "login", username: "studio", url: "network", favorite: false },
  { id: "6", title: "Everyday card", kind: "card", favorite: false, cardEnding: "4242", brand: "Visa" },
  // With `?many`: a vault of hundreds of items, longer than any window.
  ...(previewAsks("many") ? Array.from({ length: 400 }, (_, index) => ({ id: `many-${index + 1}`, title: `Sample login ${index + 1}`, kind: "login" as const, username: `user${index + 1}@example.test`, url: `site${index + 1}.example`, favorite: false })) : []),
] satisfies VaultEntry[]).map((entry) => (entry.id === "2" && previewAsks("conflict") ? { ...entry, conflict: true } : entry));

/** With `?conflict`: the two versions of GitHub that were changed independently. */
const previewConflict: VersionSummary[] = [
  { revision: "preview-conflict-here", deleted: false, title: "GitHub", username: "northstar-labs", url: "github.com", device: "preview", thisDevice: true, differs: ["username", "password", "passkeys"] },
  { revision: "preview-conflict-there", deleted: false, title: "GitHub", username: "northstar-ops", url: "github.com", device: "3f9a1c2e", thisDevice: false, differs: ["username", "password", "passkeys"] },
];

/** With `?login-fill`: a sign-in page asking for the login saved for its address. */
let previewLoginFill: FillAsked | null = previewAsks("login-fill") ? {
  requestId: "preview-login-fill", origin: "https://github.com", browser: "Chromium", secondsLeft: 120, session: "preview",
  logins: [{ id: "2", title: "GitHub", username: "northstar-labs", url: "https://github.com", conflict: false }], notOffered: [],
} : null;

/** With `?card-fill`: a checkout page asking for a card, its number and code in a payment provider's frame. */
let previewCardFill: FillAsked | null = previewAsks("card-fill") ? {
  requestId: "preview-card-fill", origin: "https://shop.example", browser: "Chromium", secondsLeft: 120, session: "preview",
  logins: [], notOffered: [],
  card: {
    documents: [
      { origin: "https://shop.example", page: true, fields: ["cardholder", "expiry_month", "expiry_year"] },
      { origin: "https://pay.example.net", page: false, fields: ["number", "security_code"] },
    ],
    cards: [{ id: "6", title: "Everyday card", brand: "Visa", ending: "4242" }],
  },
} : null;

/** With `?passkey-create` or `?passkey-get`: a page's request for a passkey for example.com. */
let previewPasskey: FillAsked | null = previewAsks("passkey-create") || previewAsks("passkey-get") ? {
  requestId: "preview-passkey", origin: "https://login.example.com", browser: "Chromium", secondsLeft: 120, session: "preview",
  logins: [], notOffered: [],
  passkey: previewAsks("passkey-create") ? {
    ceremony: "create", rpId: "example.com", rpName: "Example", userName: "hello@northstar.dev", userDisplayName: "Northstar", verification: "required",
    passkeys: [], logins: [{ id: "1", title: "Proton Mail", username: "hello@northstar.dev", url: "https://example.com", conflict: false }], ownerCheck: true,
  } : {
    ceremony: "get", rpId: "example.com", rpName: "", userName: "", userDisplayName: "", verification: "discouraged",
    passkeys: [{ itemId: "2", title: "GitHub", credentialId: "cHJldmlldy1wYXNza2V5", userName: "northstar-labs", userDisplayName: "Northstar Labs" }], logins: [], ownerCheck: false,
  },
} : null;

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
let previewSettings: Settings = { autoLockMinutes: 5, generator: { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, avoidLookAlike: true } };

/**
 * The characters of each kind a password takes, and the look-alikes, as the
 * shared code names them (crates/vault-core/src/util.rs); a test of the
 * desktop app checks they are the same.
 */
const LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?";
const LOOK_ALIKES = "lIO01";

/** A random whole number below `bound`, without the bias of a remainder. */
function randomBelow(bound: number): number {
  const limit = Math.floor(0x100000000 / bound) * bound;
  const value = new Uint32Array(1);
  do crypto.getRandomValues(value); while (value[0] >= limit);
  return value[0] % bound;
}

/** The preview's generator, made as the shared code's: one character of each kind chosen, the rest of any, shuffled. */
function previewPassword(choice: GeneratorChoice): string {
  const letters = choice.lowercase || choice.uppercase;
  const sets = ([[choice.lowercase, LOWERCASE, true], [choice.uppercase, UPPERCASE, true], [choice.digits, DIGITS, letters], [choice.symbols, SYMBOLS, true]] as const)
    .filter(([chosen]) => chosen)
    .map(([, set, lookAlikesMatter]) => [...set].filter((character) => !(choice.avoidLookAlike && lookAlikesMatter && LOOK_ALIKES.includes(character))).join(""));
  if (sets.length === 0 || choice.length < sets.length || choice.length > 1024) throw new Error("invalid_item");
  const all = sets.join("");
  const characters = sets.map((set) => set[randomBelow(set.length)]);
  while (characters.length < choice.length) characters.push(all[randomBelow(all.length)]);
  for (let index = characters.length - 1; index > 0; index--) {
    const other = randomBelow(index + 1);
    [characters[index], characters[other]] = [characters[other], characters[index]];
  }
  return characters.join("");
}
/** Whether the preview's owner confirmed its warning that records were taken out of the file. */
let previewRowsConfirmed = false;

const previewDetails = new Map<string, EntryDetail>();
/** Items deleted in the preview, which it can bring back. */
let previewDeleted: VaultEntry[] = [];
const previewDeletedAt = new Map<string, number>();
/** The versions the preview's own edits made, newest first, with what each held: sample data, no secret. */
const previewHistory = new Map<string, { version: HistoryEntry; entry: VaultEntry }[]>();

function previewVersions(entry: VaultEntry): { version: HistoryEntry; entry: VaultEntry }[] {
  return previewHistory.get(entry.id) ?? [{ version: { revision: entry.revision ?? "preview", deleted: false, current: true, first: true, merged: false, title: entry.title, username: entry.username ?? "", url: entry.url ?? "", changed: [], device: "preview", thisDevice: true, savedAt: null }, entry }];
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
  const version: HistoryEntry = { revision: entry.revision ?? crypto.randomUUID(), deleted: false, current: true, first: !previous, merged: false, title: entry.title, username: entry.username ?? "", url: entry.url ?? "", changed, device: "preview", thisDevice: true, savedAt: Math.floor(Date.now() / 1000) };
  previewHistory.set(entry.id, [{ version, entry }, ...versions.map((older) => ({ ...older, version: { ...older.version, current: false } }))]);
}

/** The sample login's passkey: a site and an account, and no key. */
const PREVIEW_PASSKEY: PasskeySummary = { credentialId: "cHJldmlldy1wYXNza2V5", rpId: "github.com", userName: "northstar-labs", userDisplayName: "Northstar Labs", createdAt: 1767225600 };

/** The sample card's fields: no number or code is kept, only its last four digits. */
const PREVIEW_CARD: CardDetail = { cardholder: "Alex Northstar", expiryMonth: "08", expiryYear: "2029", brand: "Visa", numberEnding: "4242", hasNumber: true, hasSecurityCode: true };

function previewDetail(entry: VaultEntry): EntryDetail {
  return previewDetails.get(entry.id) ?? { id: entry.id, title: entry.title, kind: entry.kind, username: entry.username ?? "", url: entry.url ?? "", notes: "", favorite: Boolean(entry.favorite), hasPassword: entry.kind === "login", hasTotp: false, fields: [], card: entry.kind === "card" ? PREVIEW_CARD : null, passkeys: entry.passkeys ? [PREVIEW_PASSKEY] : [], revision: entry.revision ?? "preview" };
}

/** A card's fields after `input`, as the shell would store them, keeping of the number only its last four digits. */
function previewCard(input: NonNullable<EntryInput["card"]>, previous?: CardDetail | null): CardDetail {
  const digits = input.number === undefined ? null : cardDigits(input.number);
  const numberEnding = input.number === undefined ? previous?.numberEnding ?? null : digits ? digits.slice(-4) : null;
  return {
    cardholder: input.cardholder.trim(), expiryMonth: input.expiryMonth, expiryYear: input.expiryYear,
    brand: input.brand ?? (input.number === undefined ? previous?.brand ?? "" : cardBrand(input.number) ?? previous?.brand ?? ""),
    numberEnding,
    hasNumber: input.number === undefined ? Boolean(previous?.hasNumber) : input.number.length > 0,
    hasSecurityCode: input.securityCode === undefined ? Boolean(previous?.hasSecurityCode) : input.securityCode.length > 0,
  };
}

/** Preview writes stay in memory and never retain the password or TOTP secret. */
function savePreview(id: string, input: EntryInput, previous?: EntryDetail): VaultEntry {
  const revision = crypto.randomUUID();
  const detail: EntryDetail = {
    id, title: input.title, kind: input.kind, username: input.username, url: input.url, notes: input.notes, favorite: input.favorite,
    hasPassword: input.password !== undefined ? input.password.length > 0 : Boolean(previous?.hasPassword),
    hasTotp: input.totpSecret !== undefined ? input.totpSecret.trim().length > 0 : Boolean(previous?.hasTotp),
    fields: previous?.fields ?? [],
    card: input.kind === "card" && input.card ? previewCard(input.card, previous?.card) : input.kind === "card" ? previous?.card ?? null : null,
    passkeys: previous?.passkeys ?? [],
    revision,
  };
  previewDetails.set(id, detail);
  const entry: VaultEntry = { id, title: input.title, kind: input.kind, username: input.username || undefined, url: input.url || undefined, favorite: input.favorite, revision, cardEnding: detail.card?.numberEnding ?? null, brand: detail.card?.brand || null, passkeys: detail.passkeys?.length ?? 0 };
  recordPreviewVersion(entry, input, previous);
  previewEntries = [entry, ...previewEntries.filter((existing) => existing.id !== id)];
  return entry;
}

export function hasNativeBridge(): boolean {
  return Boolean((globalThis as { __TAURI__?: { core?: { invoke?: unknown } } }).__TAURI__?.core?.invoke);
}

/** The preview's sample invitation as a QR code, drawn as the app's `qr_of` (`src-tauri/src/qr.rs`) draws it. */
const PREVIEW_INVITATION_QR = {
  side: 37,
  path: "M4 4h7v1h-7zM12 4h2v1h-2zM16 4h1v1h-1zM18 4h2v1h-2zM21 4h1v1h-1zM26 4h7v1h-7zM4 5h1v1h-1zM10 5h1v1h-1zM14 5h2v1h-2zM17 5h1v1h-1zM19 5h1v1h-1zM21 5h2v1h-2zM24 5h1v1h-1zM26 5h1v1h-1zM32 5h1v1h-1zM4 6h1v1h-1zM6 6h3v1h-3zM10 6h1v1h-1zM12 6h1v1h-1zM20 6h3v1h-3zM26 6h1v1h-1zM28 6h3v1h-3zM32 6h1v1h-1zM4 7h1v1h-1zM6 7h3v1h-3zM10 7h1v1h-1zM12 7h4v1h-4zM17 7h1v1h-1zM19 7h4v1h-4zM24 7h1v1h-1zM26 7h1v1h-1zM28 7h3v1h-3zM32 7h1v1h-1zM4 8h1v1h-1zM6 8h3v1h-3zM10 8h1v1h-1zM13 8h7v1h-7zM21 8h1v1h-1zM23 8h2v1h-2zM26 8h1v1h-1zM28 8h3v1h-3zM32 8h1v1h-1zM4 9h1v1h-1zM10 9h1v1h-1zM12 9h1v1h-1zM15 9h3v1h-3zM22 9h1v1h-1zM26 9h1v1h-1zM32 9h1v1h-1zM4 10h7v1h-7zM12 10h1v1h-1zM14 10h1v1h-1zM16 10h1v1h-1zM18 10h1v1h-1zM20 10h1v1h-1zM22 10h1v1h-1zM24 10h1v1h-1zM26 10h7v1h-7zM12 11h3v1h-3zM16 11h1v1h-1zM20 11h2v1h-2zM24 11h1v1h-1zM5 12h1v1h-1zM7 12h1v1h-1zM9 12h6v1h-6zM20 12h2v1h-2zM25 12h3v1h-3zM29 12h2v1h-2zM32 12h1v1h-1zM8 13h1v1h-1zM11 13h4v1h-4zM16 13h4v1h-4zM24 13h1v1h-1zM26 13h2v1h-2zM30 13h2v1h-2zM4 14h1v1h-1zM6 14h1v1h-1zM9 14h4v1h-4zM15 14h4v1h-4zM24 14h1v1h-1zM26 14h1v1h-1zM29 14h3v1h-3zM4 15h4v1h-4zM9 15h1v1h-1zM12 15h2v1h-2zM15 15h1v1h-1zM18 15h2v1h-2zM21 15h1v1h-1zM23 15h3v1h-3zM28 15h2v1h-2zM5 16h1v1h-1zM8 16h1v1h-1zM10 16h2v1h-2zM13 16h1v1h-1zM16 16h1v1h-1zM18 16h1v1h-1zM20 16h1v1h-1zM22 16h2v1h-2zM25 16h2v1h-2zM30 16h3v1h-3zM4 17h1v1h-1zM7 17h2v1h-2zM11 17h2v1h-2zM14 17h1v1h-1zM16 17h3v1h-3zM20 17h1v1h-1zM22 17h1v1h-1zM24 17h1v1h-1zM26 17h2v1h-2zM30 17h3v1h-3zM5 18h2v1h-2zM8 18h1v1h-1zM10 18h4v1h-4zM15 18h1v1h-1zM19 18h1v1h-1zM25 18h3v1h-3zM31 18h2v1h-2zM5 19h1v1h-1zM8 19h1v1h-1zM11 19h3v1h-3zM15 19h2v1h-2zM18 19h1v1h-1zM20 19h3v1h-3zM25 19h1v1h-1zM27 19h3v1h-3zM32 19h1v1h-1zM4 20h3v1h-3zM8 20h1v1h-1zM10 20h1v1h-1zM13 20h2v1h-2zM22 20h1v1h-1zM24 20h1v1h-1zM27 20h6v1h-6zM5 21h3v1h-3zM9 21h1v1h-1zM11 21h3v1h-3zM15 21h1v1h-1zM19 21h3v1h-3zM23 21h1v1h-1zM29 21h1v1h-1zM31 21h1v1h-1zM4 22h1v1h-1zM6 22h2v1h-2zM9 22h3v1h-3zM13 22h3v1h-3zM17 22h1v1h-1zM19 22h2v1h-2zM22 22h1v1h-1zM25 22h2v1h-2zM31 22h2v1h-2zM6 23h1v1h-1zM8 23h1v1h-1zM11 23h3v1h-3zM15 23h3v1h-3zM22 23h2v1h-2zM25 23h1v1h-1zM28 23h1v1h-1zM30 23h1v1h-1zM32 23h1v1h-1zM4 24h1v1h-1zM7 24h1v1h-1zM9 24h3v1h-3zM13 24h1v1h-1zM16 24h1v1h-1zM19 24h1v1h-1zM23 24h10v1h-10zM12 25h3v1h-3zM16 25h2v1h-2zM19 25h2v1h-2zM23 25h2v1h-2zM28 25h1v1h-1zM30 25h1v1h-1zM32 25h1v1h-1zM4 26h7v1h-7zM12 26h2v1h-2zM16 26h2v1h-2zM19 26h3v1h-3zM23 26h2v1h-2zM26 26h1v1h-1zM28 26h1v1h-1zM31 26h2v1h-2zM4 27h1v1h-1zM10 27h1v1h-1zM12 27h3v1h-3zM17 27h5v1h-5zM23 27h2v1h-2zM28 27h3v1h-3zM4 28h1v1h-1zM6 28h3v1h-3zM10 28h1v1h-1zM14 28h2v1h-2zM18 28h2v1h-2zM24 28h8v1h-8zM4 29h1v1h-1zM6 29h3v1h-3zM10 29h1v1h-1zM12 29h1v1h-1zM14 29h3v1h-3zM18 29h3v1h-3zM25 29h1v1h-1zM29 29h2v1h-2zM32 29h1v1h-1zM4 30h1v1h-1zM6 30h3v1h-3zM10 30h1v1h-1zM13 30h1v1h-1zM15 30h4v1h-4zM21 30h1v1h-1zM25 30h2v1h-2zM32 30h1v1h-1zM4 31h1v1h-1zM10 31h1v1h-1zM12 31h2v1h-2zM15 31h2v1h-2zM18 31h2v1h-2zM23 31h1v1h-1zM25 31h2v1h-2zM28 31h1v1h-1zM30 31h3v1h-3zM4 32h7v1h-7zM14 32h3v1h-3zM20 32h2v1h-2zM23 32h4v1h-4z",
};

/**
 * The preview keeps the interface useful in a browser. Tauri injects the
 * command bridge in production; no secret is placed in this fallback data.
 */
/** The turn of the last call handing the time without activity over (lockWhenIdle). */
let handOverTurn = 0;

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
  async passwordHealth() {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return (await invoke("password_health")) as PasswordHealth;
    // The preview keeps no password, so it answers with a sample: a short
    // password on the Wi-Fi login, and one shared by the two first logins.
    return { weak: [{ id: "5", reasons: ["too_short", "one_kind"] }], reused: [["1", "2"]] };
  },
  async lock() {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) await invoke("lock_vault");
  },
  async lockWhenIdle(milliseconds) {
    const invoke = native();
    // The time of the call orders it among the others, which the native
    // side can take out of order; two in the same millisecond are kept apart.
    handOverTurn = Math.max(performance.timeOrigin + performance.now(), handOverTurn + 0.001);
    if (invoke) await invoke("lock_when_idle", { milliseconds, turn: handOverTurn });
    // The preview has no native side: what it would have been handed is
    // kept where the window's tests can read it.
    else (globalThis as { osmHandedOver?: number | null }).osmHandedOver = milliseconds;
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
  async generatePassword(choice) {
    const invoke = native();
    if (invoke) return String(await invoke("generate_password", { choice }));
    return previewPassword(choice);
  },
  copyGenerated: (value) => nativeOnly("copy_generated", { value }),
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
  async removePasskey(id, expectedRevision, credentialId) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) return (await invoke("remove_passkey", { id, expectedRevision, credentialId })) as VaultEntry;
    const entry = previewEntries.find((existing) => existing.id === id);
    if (!entry) throw new Error("not_found");
    const detail = previewDetail(entry);
    const passkeys = (detail.passkeys ?? []).filter((passkey) => passkey.credentialId !== credentialId);
    const revision = crypto.randomUUID();
    previewDetails.set(id, { ...detail, passkeys, revision });
    const updated: VaultEntry = { ...entry, revision, passkeys: passkeys.length };
    previewEntries = previewEntries.map((existing) => existing.id === id ? updated : existing);
    return updated;
  },
  async deleteEntry(id, expectedRevision) {
    const invoke = (globalThis as { __TAURI__?: { core?: { invoke?: (cmd: string, args?: unknown) => Promise<unknown> } } }).__TAURI__?.core?.invoke;
    if (invoke) { await invoke("delete_entry", { id, expectedRevision }); return; }
    const gone = previewEntries.find((existing) => existing.id === id);
    if (!gone) throw new Error("not_found");
    previewEntries = previewEntries.filter((existing) => existing.id !== id);
    previewDeleted = [gone, ...previewDeleted];
    previewDeletedAt.set(id, Math.floor(Date.now() / 1000));
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
    if (!previewHasDevices()) return { setup: "none", members: [], epoch: 0, quorum: 0 };
    const members = previewAsks("without-vote") ? previewDevices.members.map((member) => ({ ...member, votes: !member.votes, leader: !member.leader })) : previewDevices.members;
    return { ...previewDevices, members, relay: previewRelay };
  },
  // The preview's relay is sample data: no connection is made.
  async setRelay(code) {
    const invoke = native();
    if (invoke) { await invoke("set_relay", { code }); return; }
    if (code !== null && !code.trim().startsWith("OSM-RELAY1-")) throw Object.assign(new Error("invalid_relay_code"), { code: "invalid_relay_code" });
    previewRelay = code === null ? null : { address: "relay.example:47830", connected: true };
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
  /** The preview's last backup was 45 days ago with `?backup-due`, there is none with `?no-backup`, and it is recent otherwise. */
  async backupAge() {
    const invoke = native();
    if (invoke) return (await invoke("backup_age")) as BackupAge;
    if (previewAsks("no-backup")) return { days: null, due: true, device: null };
    return previewAsks("backup-due") ? { days: 45, due: true, device: null } : { days: 2, due: false, device: null };
  },
  chooseBackup: () => nativeOnly("choose_backup"),
  restoreBackup: (recoveryKey, password) => nativeOnly("restore_backup", { recoveryKey, password }),
  resetPassword: (recoveryKey, newPassword) => nativeOnly("reset_password", { recoveryKey, newPassword }),
  /** The preview, whose unlock takes any password, takes any current one, and keeps nothing. */
  async changePassword(currentPassword, newPassword) {
    const invoke = native();
    if (invoke) { await invoke("change_password", { currentPassword, newPassword }); return; }
    if (newPassword.length < 12) throw Object.assign(new Error("use at least 12 characters for this device password"), { code: "invalid_item" });
  },
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
  // has one only when its address asks (`?login-fill`, `?card-fill`,
  // `?passkey-create`, `?passkey-get`).
  async fillRequest() {
    const invoke = native();
    return invoke ? ((await invoke("fill_request")) as FillAsked | null) : previewLoginFill ?? previewCardFill ?? previewPasskey;
  },
  async approveFill(requestId, itemId, session) {
    const invoke = native();
    if (invoke) { await invoke("approve_fill", { requestId, itemId, session }); return; }
    if (!previewLoginFill) throw new Error("preview");
    previewLoginFill = null;
  },
  async approveCard(requestId, itemId, session) {
    const invoke = native();
    if (invoke) { await invoke("approve_card", { requestId, itemId, session }); return; }
    previewCardFill = null;
  },
  async approvePasskey(requestId, session, choice) {
    const invoke = native();
    if (invoke) {
      await invoke("approve_passkey", { requestId, session, into: choice.into ?? null, itemId: choice.itemId ?? null, credentialId: choice.credentialId ?? null, password: choice.password ?? null, ownerCheck: Boolean(choice.ownerCheck) });
      return;
    }
    // The preview's device password is anything but empty; a site that asks
    // to verify the owner gets nothing without it or the system's check.
    if (previewPasskey?.passkey?.verification !== "discouraged" && !choice.ownerCheck && !choice.password) throw { code: "not_verified" };
    if (choice.password === "wrong") throw { code: "wrong_password" };
    previewPasskey = null;
  },
  async useBrowserPasskey(requestId) {
    const invoke = native();
    if (invoke) { await invoke("use_browser_passkey", { requestId }); return; }
    previewPasskey = null;
  },
  async denyFill(requestId) {
    const invoke = native();
    if (invoke) { await invoke("deny_fill", { requestId }); return; }
    if (previewLoginFill) { previewLoginFill = null; return; }
    if (previewCardFill) { previewCardFill = null; return; }
    if (previewPasskey) { previewPasskey = null; return; }
    throw new Error("preview");
  },
  async browserStatus() {
    const invoke = native();
    if (invoke) return (await invoke("browser_status")) as BrowserStatus;
    return { supported: false, listening: false, problem: null, host: null, temporaryPlace: false, browsers: [] };
  },
  connectBrowser: (browser) => nativeOnly("connect_browser", { browser }),
  disconnectBrowser: (browser) => nativeOnly("disconnect_browser", { browser }),
  /** With `?devices`, a sample invitation that pairs nothing. */
  async startInvite(votes, away) {
    if (native() || !previewHasDevices()) return nativeOnly("start_invite", { votes, away: away ?? false });
    return { code: "OSM-PAIR1-PREVIEW-SAMPLE-NOT-AN-INVITATION", expiresAt: Date.now() + 15 * 60_000, qr: PREVIEW_INVITATION_QR };
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
    return previewDeleted.map((entry) => ({ id: entry.id, title: entry.title, kind: entry.kind, username: entry.username ?? "", url: entry.url ?? "", last: entry.revision ?? "preview", heads: ["preview-deletion"], device: "preview", thisDevice: true, deletedAt: previewDeletedAt.get(entry.id) ?? null }));
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
      previewHistory.set(id, [{ version: { ...earlier.version, revision: restored.revision ?? "", current: true, first: false, changed, savedAt: Math.floor(Date.now() / 1000) }, entry: restored }, ...versions]);
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
    previewSettings = { ...previewSettings, autoLockMinutes: minutes };
    return previewSettings;
  },
  async setGenerator(choice) {
    const invoke = native();
    if (invoke) return (await invoke("set_generator", { choice })) as Settings;
    previewSettings = { ...previewSettings, generator: choice };
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
