import type { DesktopBridge, VaultEntry } from "./types";

const previewEntries: VaultEntry[] = [
  { id: "1", title: "Proton Mail", kind: "login", username: "hello@northstar.dev", url: "proton.me", updatedAt: "Today, 09:42", favorite: true },
  { id: "2", title: "GitHub", kind: "login", username: "northstar-labs", url: "github.com", updatedAt: "Yesterday, 18:10", favorite: true },
  { id: "3", title: "Banking — checking", kind: "login", username: "•••• 4821", url: "secure.bank.example", updatedAt: "Sep 18", favorite: false },
  { id: "4", title: "Recovery codes", kind: "secure_note", updatedAt: "Sep 12", favorite: false },
  { id: "5", title: "Studio Wi-Fi", kind: "login", username: "studio", url: "network", updatedAt: "Aug 27", favorite: false },
];

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
};
