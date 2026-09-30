import { useEffect, useMemo, useState } from "react";
import { Archive, ArrowDownToLine, ChevronRight, CircleAlert, Clock3, Copy, Fingerprint, KeyRound, LockKeyhole, MoreHorizontal, Plus, Search, ShieldCheck, Sparkles, UnlockKeyhole, Wifi, X } from "lucide-react";
import { bridge, hasNativeBridge } from "./bridge";
import type { SyncState, VaultEntry } from "./types";

const filters = ["All items", "Favorites", "Logins", "Secure notes"] as const;
type Filter = (typeof filters)[number];

function App() {
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [locked, setLocked] = useState(false);
  const [vaultStatus, setVaultStatus] = useState<"missing" | "locked" | "unlocked">("unlocked");
  const [unlockPassword, setUnlockPassword] = useState("");
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [previewMode] = useState(() => !hasNativeBridge());
  const [selected, setSelected] = useState("1");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("All items");
  const [sync] = useState<SyncState>("offline");
  const [notice, setNotice] = useState<string | null>(null);
  const [generatorOpen, setGeneratorOpen] = useState(false);

  useEffect(() => {
    void bridge.status().then(async (status) => {
      setVaultStatus(status);
      setLocked(status !== "unlocked");
      if (status === "unlocked") setEntries(await bridge.listEntries());
    }).catch(() => { setVaultStatus("missing"); setLocked(true); });
  }, []);
  useEffect(() => {
    let timer = window.setTimeout(() => { void bridge.lock(); setEntries([]); setLocked(true); setRecoveryKey(null); }, 5 * 60 * 1000);
    const reset = () => { window.clearTimeout(timer); timer = window.setTimeout(() => { void bridge.lock(); setEntries([]); setLocked(true); setRecoveryKey(null); }, 5 * 60 * 1000); };
    const onVisibility = () => { if (document.visibilityState === "hidden") { void bridge.lock(); setEntries([]); setLocked(true); setRecoveryKey(null); } else reset(); };
    for (const event of ["pointerdown", "keydown", "touchstart"]) window.addEventListener(event, reset, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    return () => { window.clearTimeout(timer); for (const event of ["pointerdown", "keydown", "touchstart"]) window.removeEventListener(event, reset); document.removeEventListener("visibilitychange", onVisibility); };
  }, []);
  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 3200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const visible = useMemo(() => entries.filter((entry) => {
    const matchesQuery = `${entry.title} ${entry.username ?? ""} ${entry.url ?? ""}`.toLowerCase().includes(query.toLowerCase());
    const matchesFilter = filter === "All items" || (filter === "Favorites" && entry.favorite) || (filter === "Logins" && entry.kind === "login") || (filter === "Secure notes" && entry.kind === "secure_note");
    return matchesQuery && matchesFilter;
  }), [entries, filter, query]);
  const active = entries.find((entry) => entry.id === selected) ?? visible[0];

  async function copyTotp() {
    if (!active) return;
    if (previewMode) {
      setNotice("TOTP copy is unavailable in the browser preview");
      return;
    }
    try {
      await bridge.copyTotp(active.id);
      setNotice("One-time code copied · clears in 30 seconds");
    } catch {
      setNotice("TOTP clipboard is unavailable while the native adapter is not installed");
    }
  }

  async function lock() {
    await bridge.lock();
    setEntries([]);
    setLocked(true);
    setRecoveryKey(null);
    setNotice("Vault locked");
  }

  async function unlock() {
    if (!unlockPassword) return;
    try {
      await bridge.unlock(unlockPassword);
      setUnlockPassword("");
      setEntries(await bridge.listEntries());
      setLocked(false);
      setVaultStatus("unlocked");
      setNotice("Vault unlocked");
    } catch {
      setNotice("That unlock password was rejected");
    }
  }

  async function createVault() {
    if (unlockPassword.length < 12) { setNotice("Use at least 12 characters for this device password"); return; }
    try {
      const recovery = await bridge.createVault(unlockPassword);
      if (recovery) setRecoveryKey(recovery);
      setUnlockPassword("");
      setVaultStatus("unlocked");
      setLocked(false);
      setNotice("Vault created · store the recovery key offline");
    } catch {
      setNotice("The vault could not be created at this location");
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark"><KeyRound size={17} strokeWidth={2.5} /></div><span>open secret</span><span className="brand-dot">·</span></div>
        <div className="vault-chip"><div className="vault-emblem"><ShieldCheck size={16} /></div><div><strong>Personal vault</strong><span>{previewMode ? "Development preview · local only" : "Owner device · local only"}</span></div><ChevronRight size={15} className="muted" /></div>
        <button className="new-item" onClick={() => setNotice("Choose a record type to create") }><Plus size={17} /> New item <span>⌘ N</span></button>
        <nav className="nav-list" aria-label="Vault filters">
          <p className="nav-caption">YOUR VAULT <span>{entries.length}</span></p>
          {filters.map((item) => <button key={item} className={`nav-item ${filter === item ? "active" : ""}`} onClick={() => setFilter(item)}><span className={`nav-icon ${item === "Favorites" ? "star" : ""}`}>{item === "All items" ? "⌂" : item === "Favorites" ? "★" : item === "Logins" ? "↗" : "▤"}</span>{item}<span className="nav-count">{item === "All items" ? entries.length : item === "Favorites" ? entries.filter((e) => e.favorite).length : item === "Logins" ? entries.filter((e) => e.kind === "login").length : entries.filter((e) => e.kind === "secure_note").length}</span></button>)}
        </nav>
        <div className="sidebar-bottom"><button className="utility" onClick={() => setGeneratorOpen(true)}><Sparkles size={16} /> Generator</button><button className="utility"><Archive size={16} /> Archive</button><button className="utility"><Clock3 size={16} /> Activity</button><button className="utility"><MoreHorizontal size={16} /> Settings</button><div className="device-card"><div className="device-icon"><Fingerprint size={18} /></div><div><strong>This device</strong><span>{previewMode ? "Preview data only" : "Sync adapter pending"}</span></div><span className="online-dot offline-dot" /></div></div>
      </aside>

      <section className="content-pane">
        <header className="topbar"><div className="breadcrumbs"><span>Personal vault</span><ChevronRight size={15} /><strong>{filter}</strong></div><div className="top-actions"><div className={`sync-status ${sync}`}><span className="status-dot" />{sync === "connected" ? "Synced" : sync === "received" ? "Received · unlock to apply" : "Offline"}</div><button className="icon-button" title="Lock vault" onClick={lock}><LockKeyhole size={18} /></button><div className="avatar">YK</div></div></header>
        <div className="workspace">
          <div className="list-column">
            <div className="list-heading"><div><p className="eyebrow">{filter.toUpperCase()}</p><h1>{visible.length} <span>items</span></h1></div><button className="icon-button bordered" title="Import"><ArrowDownToLine size={17} /></button></div>
            <label className="search-box"><Search size={17} /><input aria-label="Search vault" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search your vault" /><kbd>⌘ K</kbd></label>
            <div className="entry-list">{visible.map((entry) => <button key={entry.id} className={`entry-row ${active?.id === entry.id ? "selected" : ""}`} onClick={() => setSelected(entry.id)}><div className={`entry-logo logo-${entry.kind}`}>{entry.kind === "secure_note" ? "▤" : entry.title.slice(0, 1)}</div><div className="entry-copy"><strong>{entry.title}</strong><span>{entry.username ?? "Secure note"}</span></div><div className="entry-meta">{entry.favorite && <span className="favorite">★</span>}<small>{entry.updatedAt}</small></div></button>)}{visible.length === 0 && <div className="empty-list"><Search size={22} /><strong>No matching items</strong><span>Try a different search or filter.</span></div>}</div>
          </div>
          <div className="detail-column">{locked ? <div className="empty-detail">{vaultStatus === "missing" ? <><Sparkles size={25} /><h2>Create your encrypted vault</h2><span>This device keeps its own vault. Choose a strong local password.</span></> : <><LockKeyhole size={25} /><h2>Vault locked</h2><span>Unlock in the desktop window to view encrypted records.</span></>}<div className="unlock-form"><input aria-label="Vault password" type="password" placeholder={vaultStatus === "missing" ? "New device password" : "Vault password"} value={unlockPassword} onChange={(event) => setUnlockPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void (vaultStatus === "missing" ? createVault() : unlock()); }} /><button onClick={() => void (vaultStatus === "missing" ? createVault() : unlock())}>{vaultStatus === "missing" ? <><Plus size={15} /> Create</> : <><UnlockKeyhole size={15} /> Unlock</>}</button></div></div> : active ? <><div className="detail-head"><div className={`detail-logo logo-${active.kind}`}>{active.kind === "secure_note" ? "▤" : active.title.slice(0, 1)}</div><div className="detail-title"><div><h2>{active.title}</h2>{active.url && <span>{active.url}</span>}</div><button className="icon-button"><MoreHorizontal size={19} /></button></div></div><div className="detail-actions"><button onClick={() => setNotice("Edit mode is ready in the desktop shell")}><span className="action-icon">✎</span> Edit</button><button onClick={copyTotp}><Copy size={15} /> Copy TOTP</button><button onClick={() => setNotice("Item link copied")}>Share <span className="action-arrow">↗</span></button></div><div className="record-card"><RecordField label="Username" value={active.username ?? "—"} /><RecordField label="Password" value="••••••••••••••" secret /><RecordField label="Website" value={active.url ?? "—"} link /></div><div className="history-note"><Clock3 size={15} /><div><strong>Revision history is retained</strong><span>Every edit keeps its signed parent revision.</span></div><ChevronRight size={15} /></div>{active.conflict && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Needs your decision</strong><span>Two signed revisions changed this item concurrently. Autofill is paused.</span></div></div>}</> : <div className="empty-detail"><Sparkles size={25} /><h2>Select an item</h2><span>Your encrypted record will appear here after selection.</span></div>}</div>
        </div>
        {recoveryKey && !locked && <div className="recovery-overlay"><div className="recovery-card"><strong>Recovery key · store this offline</strong><code>{recoveryKey}</code><span>It will be cleared when you acknowledge it or the vault locks.</span><button onClick={() => setRecoveryKey(null)}>I stored it</button></div></div>}
        <footer className="footer-bar"><div><Wifi size={14} /><span>{previewMode ? "Development preview" : "Local vault"}</span><span className="footer-separator">•</span><span>{previewMode ? "No native sync session" : "Sync adapter pending"}</span></div><button onClick={() => setNotice(previewMode ? "Sync activity is unavailable in the browser preview" : "Sync transport is not connected yet")}>View activity <ChevronRight size={14} /></button></footer>
      </section>
      {generatorOpen && <div className="modal-backdrop" onClick={() => setGeneratorOpen(false)}><div className="generator-modal" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">TOOLS</p><h2>Password generator</h2></div><button className="icon-button" onClick={() => setGeneratorOpen(false)}><X size={18} /></button></div><Generator onCopy={(value) => { navigator.clipboard?.writeText(value); setNotice("Generated password copied"); }} /></div></div>}
      {notice && <div className="toast"><ShieldCheck size={15} />{notice}</div>}
    </main>
  );
}

function RecordField({ label, value, secret, link }: { label: string; value: string; secret?: boolean; link?: boolean }) {
  return <div className="record-field"><label>{label}</label><div><span className={secret ? "masked" : link ? "record-link" : ""}>{value}</span>{secret ? <button className="field-action" onClick={() => navigator.clipboard?.writeText(value)}> <Copy size={14} /> </button> : link ? <span className="external">↗</span> : null}</div></div>;
}

function Generator({ onCopy }: { onCopy: (value: string) => void }) {
  const [length, setLength] = useState(20);
  const [value, setValue] = useState("");
  async function generate() { const next = await bridge.generatePassword(length); setValue(next); }
  return <div className="generator"><div className="generated-value"><code>{value || "Generate a fresh password"}</code><button disabled={!value} onClick={() => onCopy(value)}><Copy size={16} /></button></div><label className="range-label">Length <strong>{length}</strong></label><input type="range" min="12" max="48" value={length} onChange={(event) => setLength(Number(event.target.value))} /><div className="generator-options"><span>Uppercase</span><span>Numbers</span><span>Symbols</span></div><button className="generate-button" onClick={generate}><Sparkles size={16} /> Generate new password</button></div>;
}

export default App;
