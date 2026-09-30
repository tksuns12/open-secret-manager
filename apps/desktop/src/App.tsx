import { useEffect, useMemo, useState } from "react";
import { Archive, ArrowDownToLine, ChevronRight, CircleAlert, Clock3, Copy, Eye, EyeOff, Fingerprint, KeyRound, LockKeyhole, MoreHorizontal, Plus, Search, ShieldCheck, Sparkles, UnlockKeyhole, Wifi, X } from "lucide-react";
import { bridge, hasNativeBridge } from "./bridge";
import type { EntryDetail, EntryInput, EntryKind, SyncState, VaultEntry, VersionSummary } from "./types";

const filters = ["All items", "Favorites", "Logins", "Secure notes"] as const;
type Filter = (typeof filters)[number];
type EditorState = { mode: "create" } | { mode: "edit"; detail: EntryDetail };
type ReviewState = { id: string; title: string; versions: VersionSummary[] };

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
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [review, setReview] = useState<ReviewState | null>(null);

  useEffect(() => {
    void bridge.status().then(async (status) => {
      setVaultStatus(status);
      setLocked(status !== "unlocked");
      if (status === "unlocked") setEntries(await bridge.listEntries());
    }).catch(() => { setVaultStatus("missing"); setLocked(true); });
  }, []);
  useEffect(() => {
    let timer = window.setTimeout(() => { void bridge.lock(); setEntries([]); setLocked(true); setRecoveryKey(null); setEditor(null); setReview(null); }, 5 * 60 * 1000);
    const reset = () => { window.clearTimeout(timer); timer = window.setTimeout(() => { void bridge.lock(); setEntries([]); setLocked(true); setRecoveryKey(null); setEditor(null); setReview(null); }, 5 * 60 * 1000); };
    const onVisibility = () => { if (document.visibilityState === "hidden") { void bridge.lock(); setEntries([]); setLocked(true); setRecoveryKey(null); setEditor(null); setReview(null); } else reset(); };
    for (const event of ["pointerdown", "keydown", "touchstart"]) window.addEventListener(event, reset, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    return () => { window.clearTimeout(timer); for (const event of ["pointerdown", "keydown", "touchstart"]) window.removeEventListener(event, reset); document.removeEventListener("visibilitychange", onVisibility); };
  }, []);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "n" && !locked) { event.preventDefault(); setEditor({ mode: "create" }); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [locked]);
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

  async function openReview() {
    if (!active) return;
    try {
      setReview({ id: active.id, title: active.title, versions: await bridge.listVersions(active.id) });
    } catch (error) {
      setNotice(commandMessage(error, "The conflicting versions could not be loaded"));
    }
  }

  async function keepVersion(revision: string) {
    if (!review) return;
    try {
      // Name exactly the versions that were shown; one that arrived since
      // stays visible rather than being discarded unseen.
      await bridge.resolveEntry(review.id, revision, review.versions.map((version) => version.revision));
      setEntries(await bridge.listEntries());
      setReview(null);
      setNotice("Conflict resolved");
    } catch (error) {
      setNotice(commandMessage(error, "The conflict could not be resolved"));
    }
  }

  async function openEditor() {
    if (!active) return;
    if (active.conflict) { await openReview(); return; }
    try {
      setEditor({ mode: "edit", detail: await bridge.getEntry(active.id) });
    } catch (error) {
      setNotice(commandMessage(error, "This item could not be opened"));
    }
  }

  async function saveEntry(input: EntryInput) {
    try {
      const saved = editor?.mode === "edit"
        ? await bridge.updateEntry(editor.detail.id, editor.detail.revision, input)
        : await bridge.createEntry(input);
      setEntries(await bridge.listEntries());
      setSelected(saved.id);
      setEditor(null);
      setNotice(editor?.mode === "edit" ? "Changes saved" : "Item created");
    } catch (error) {
      setNotice(commandMessage(error, "The item could not be saved"));
    }
  }

  async function lock() {
    await bridge.lock();
    setEntries([]);
    setLocked(true);
    setRecoveryKey(null);
    setEditor(null);
    setReview(null);
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
        <button className="new-item" onClick={() => { if (!locked) setEditor({ mode: "create" }); }} disabled={locked}><Plus size={17} /> New item <span>⌘ N</span></button>
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
          <div className="detail-column">{locked ? <div className="empty-detail">{vaultStatus === "missing" ? <><Sparkles size={25} /><h2>Create your encrypted vault</h2><span>This device keeps its own vault. Choose a strong local password.</span></> : <><LockKeyhole size={25} /><h2>Vault locked</h2><span>Unlock in the desktop window to view encrypted records.</span></>}<div className="unlock-form"><input aria-label="Vault password" type="password" placeholder={vaultStatus === "missing" ? "New device password" : "Vault password"} value={unlockPassword} onChange={(event) => setUnlockPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void (vaultStatus === "missing" ? createVault() : unlock()); }} /><button onClick={() => void (vaultStatus === "missing" ? createVault() : unlock())}>{vaultStatus === "missing" ? <><Plus size={15} /> Create</> : <><UnlockKeyhole size={15} /> Unlock</>}</button></div></div> : active ? <><div className="detail-head"><div className={`detail-logo logo-${active.kind}`}>{active.kind === "secure_note" ? "▤" : active.title.slice(0, 1)}</div><div className="detail-title"><div><h2>{active.title}</h2>{active.url && <span>{active.url}</span>}</div><button className="icon-button"><MoreHorizontal size={19} /></button></div></div><div className="detail-actions"><button onClick={() => void openEditor()}><span className="action-icon">✎</span> Edit</button><button onClick={copyTotp}><Copy size={15} /> Copy TOTP</button><button onClick={() => setNotice("Item link copied")}>Share <span className="action-arrow">↗</span></button></div><div className="record-card"><RecordField label="Username" value={active.username ?? "—"} /><RecordField label="Password" value="••••••••••••••" secret /><RecordField label="Website" value={active.url ?? "—"} link /></div><div className="history-note"><Clock3 size={15} /><div><strong>Revision history is retained</strong><span>Every edit keeps its signed parent revision.</span></div><ChevronRight size={15} /></div>{active.conflict && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Needs your decision</strong><span>Two signed revisions changed this item concurrently. Autofill is paused.</span></div><button className="conflict-action" onClick={() => void openReview()}>Review versions</button></div>}</> : <div className="empty-detail"><Sparkles size={25} /><h2>Select an item</h2><span>Your encrypted record will appear here after selection.</span></div>}</div>
        </div>
        {recoveryKey && !locked && <div className="recovery-overlay"><div className="recovery-card"><strong>Recovery key · store this offline</strong><code>{recoveryKey}</code><span>It will be cleared when you acknowledge it or the vault locks.</span><button onClick={() => setRecoveryKey(null)}>I stored it</button></div></div>}
        <footer className="footer-bar"><div><Wifi size={14} /><span>{previewMode ? "Development preview" : "Local vault"}</span><span className="footer-separator">•</span><span>{previewMode ? "No native sync session" : "Sync adapter pending"}</span></div><button onClick={() => setNotice(previewMode ? "Sync activity is unavailable in the browser preview" : "Sync transport is not connected yet")}>View activity <ChevronRight size={14} /></button></footer>
      </section>
      {generatorOpen && <div className="modal-backdrop" onClick={() => setGeneratorOpen(false)}><div className="generator-modal" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">TOOLS</p><h2>Password generator</h2></div><button className="icon-button" onClick={() => setGeneratorOpen(false)}><X size={18} /></button></div><Generator onCopy={(value) => { navigator.clipboard?.writeText(value); setNotice("Generated password copied"); }} /></div></div>}
      {editor && <div className="modal-backdrop" onClick={() => setEditor(null)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">{editor.mode === "edit" ? "EDIT ITEM" : "NEW ITEM"}</p><h2>{editor.mode === "edit" ? editor.detail.title : "Create an item"}</h2></div><button className="icon-button" onClick={() => setEditor(null)}><X size={18} /></button></div><EntryEditor detail={editor.mode === "edit" ? editor.detail : undefined} onCancel={() => setEditor(null)} onSave={saveEntry} /></div></div>}
      {review && <div className="modal-backdrop" onClick={() => setReview(null)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">RESOLVE CONFLICT</p><h2>{review.title}</h2></div><button className="icon-button" onClick={() => setReview(null)}><X size={18} /></button></div><p className="review-hint">These versions were changed independently. Keep one; it replaces all of them.</p><div className="version-list">{review.versions.map((version) => <div key={version.revision} className="version-card"><div className="version-meta"><strong>{version.thisDevice ? "This device" : `Device ${version.device}`}</strong><code>{version.revision.slice(0, 10)}</code></div>{version.deleted ? <span className="version-deleted">Deleted this item</span> : <dl><dt>Title</dt><dd>{version.title}</dd><dt>Username</dt><dd>{version.username || "—"}</dd><dt>Website</dt><dd>{version.url || "—"}</dd></dl>}<button className="generate-button" onClick={() => void keepVersion(version.revision)}>{version.deleted ? "Keep deletion" : "Keep this version"}</button></div>)}</div></div></div>}
      {notice && <div className="toast"><ShieldCheck size={15} />{notice}</div>}
    </main>
  );
}

function RecordField({ label, value, secret, link }: { label: string; value: string; secret?: boolean; link?: boolean }) {
  return <div className="record-field"><label>{label}</label><div><span className={secret ? "masked" : link ? "record-link" : ""}>{value}</span>{secret ? <button className="field-action" onClick={() => navigator.clipboard?.writeText(value)}> <Copy size={14} /> </button> : link ? <span className="external">↗</span> : null}</div></div>;
}

function commandMessage(error: unknown, fallback: string): string {
  const code = (error as { code?: string } | null)?.code;
  if (code === "conflict") return "This item changed since you opened it · reopen to edit";
  if (code === "unresolved") return "This item has conflicting versions · review them first";
  if (code === "invalid_item") return (error as { message?: string }).message ?? fallback;
  if (code === "locked") return "Unlock the vault first";
  return fallback;
}

const entryKinds: { value: EntryKind; label: string }[] = [
  { value: "login", label: "Login" },
  { value: "secure_note", label: "Secure note" },
  { value: "identity", label: "Identity" },
];

function EntryEditor({ detail, onCancel, onSave }: { detail?: EntryDetail; onCancel: () => void; onSave: (input: EntryInput) => Promise<void> }) {
  const [title, setTitle] = useState(detail?.title ?? "");
  const [kind, setKind] = useState<EntryKind>(detail?.kind ?? "login");
  const [username, setUsername] = useState(detail?.username ?? "");
  const [url, setUrl] = useState(detail?.url ?? "");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [totpSecret, setTotpSecret] = useState("");
  const [removeTotp, setRemoveTotp] = useState(false);
  const [notes, setNotes] = useState(detail?.notes ?? "");
  const [favorite, setFavorite] = useState(detail?.favorite ?? false);
  const [saving, setSaving] = useState(false);

  async function generate() { setPassword(await bridge.generatePassword(20)); setShowPassword(true); }
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!title.trim() || saving) return;
    setSaving(true);
    await onSave({
      title: title.trim(), kind, username, url: url.trim(), notes, favorite,
      // Blank password/TOTP fields keep the stored value.
      password: password ? password : undefined,
      totpSecret: removeTotp ? "" : totpSecret.trim() ? totpSecret : undefined,
    });
    setSaving(false);
  }

  return <form className="entry-form" onSubmit={submit}>
    <label>Title<input autoFocus value={title} onChange={(event) => setTitle(event.target.value)} placeholder="e.g. GitHub" /></label>
    <label>Type<select value={kind} onChange={(event) => setKind(event.target.value as EntryKind)}>{entryKinds.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
    {kind !== "secure_note" && <>
      <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" /></label>
      <label>Website<input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://" autoComplete="off" /></label>
      <label>Password<div className="field-row"><input type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder={detail?.hasPassword ? "Unchanged" : ""} autoComplete="new-password" /><button type="button" className="icon-button" title={showPassword ? "Hide" : "Show"} onClick={() => setShowPassword(!showPassword)}>{showPassword ? <EyeOff size={15} /> : <Eye size={15} />}</button><button type="button" className="icon-button" title="Generate" onClick={() => void generate()}><Sparkles size={15} /></button></div></label>
      <label>TOTP secret<input type="password" value={totpSecret} disabled={removeTotp} onChange={(event) => setTotpSecret(event.target.value)} placeholder={detail?.hasTotp ? "Unchanged" : "Base32 secret (optional)"} autoComplete="off" /></label>
      {detail?.hasTotp && <label className="check-row"><input type="checkbox" checked={removeTotp} onChange={(event) => setRemoveTotp(event.target.checked)} /> Remove one-time code</label>}
    </>}
    <label>Notes<textarea rows={kind === "secure_note" ? 7 : 3} value={notes} onChange={(event) => setNotes(event.target.value)} /></label>
    <label className="check-row"><input type="checkbox" checked={favorite} onChange={(event) => setFavorite(event.target.checked)} /> Favorite</label>
    <div className="form-actions"><button type="button" className="secondary" onClick={onCancel}>Cancel</button><button type="submit" className="generate-button" disabled={!title.trim() || saving}>{detail ? "Save changes" : "Create item"}</button></div>
  </form>;
}

function Generator({ onCopy }: { onCopy: (value: string) => void }) {
  const [length, setLength] = useState(20);
  const [value, setValue] = useState("");
  async function generate() { const next = await bridge.generatePassword(length); setValue(next); }
  return <div className="generator"><div className="generated-value"><code>{value || "Generate a fresh password"}</code><button disabled={!value} onClick={() => onCopy(value)}><Copy size={16} /></button></div><label className="range-label">Length <strong>{length}</strong></label><input type="range" min="12" max="48" value={length} onChange={(event) => setLength(Number(event.target.value))} /><div className="generator-options"><span>Uppercase</span><span>Numbers</span><span>Symbols</span></div><button className="generate-button" onClick={generate}><Sparkles size={16} /> Generate new password</button></div>;
}

export default App;
