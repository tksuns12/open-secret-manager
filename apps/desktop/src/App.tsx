import { useEffect, useMemo, useState } from "react";
import { Archive, ArrowDownToLine, ChevronRight, CircleAlert, Clock3, Copy, Eye, EyeOff, Fingerprint, KeyRound, LockKeyhole, MoreHorizontal, Plus, Search, ShieldCheck, Sparkles, UnlockKeyhole, Wifi, X } from "lucide-react";
import { bridge, hasNativeBridge } from "./bridge";
import type { DevicesInfo, EntryDetail, EntryInput, EntryKind, SyncState, SyncStatus, VaultEntry, VersionSummary } from "./types";

const filters = ["All items", "Favorites", "Logins", "Secure notes"] as const;
type Filter = (typeof filters)[number];
type EditorState = { mode: "create" } | { mode: "edit"; detail: EntryDetail };
type ReviewState = { id: string; title: string; versions: VersionSummary[] };
type InviteState = { code: string; sas?: string };

/** Topbar wording and colour for each sync state. */
function syncLabel(status: SyncStatus): { tone: SyncState; text: string } {
  switch (status.state) {
    case "synced": return { tone: "connected", text: "Synced" };
    case "idle": return { tone: "connected", text: "Devices linked" };
    case "syncing": return { tone: "received", text: "Syncing…" };
    case "received": return { tone: "received", text: "Received · unlock to apply" };
    case "error": return { tone: "offline", text: "Sync failed" };
    case "removed": return { tone: "offline", text: "Removed from vault" };
    default: return { tone: "offline", text: "Local only" };
  }
}

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
  const [sync, setSync] = useState<SyncStatus>({ state: "local", devices: 0, pending: 0 });
  const [devices, setDevices] = useState<DevicesInfo>({ setup: "none", members: [], epoch: 0, quorum: 0 });
  const [devicesOpen, setDevicesOpen] = useState(false);
  const [invite, setInvite] = useState<InviteState | null>(null);
  const [joining, setJoining] = useState(false);
  const [recoveryOn, setRecoveryOn] = useState(true);
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
    void bridge.syncStatus().then(setSync).catch(() => {});
    const loadDevices = () => { void bridge.devices().then(setDevices).catch(() => {}); };
    loadDevices();
    const subscriptions = [
      bridge.listen<SyncStatus>("sync-status", setSync),
      bridge.listen("devices-changed", loadDevices),
      // A sync merged revisions: reload the list if the vault is readable.
      bridge.listen("vault-changed", () => {
        void bridge.status().then(async (status) => { if (status === "unlocked") setEntries(await bridge.listEntries()); });
      }),
      bridge.listen<string>("pairing-code", (sas) => setInvite((current) => current && { ...current, sas })),
      bridge.listen<{ paired: boolean; code?: string; message?: string }>("pairing-finished", (result) => {
        setInvite(null);
        loadDevices();
        setNotice(result.paired ? "Device accepted · it joins once it has caught up" : commandMessage(result, "Pairing was not completed"));
      }),
    ];
    return () => { for (const subscription of subscriptions) void subscription.then((unlisten) => unlisten()); };
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
    if (!devicesOpen) return;
    void bridge.recoveryStatus().then(setRecoveryOn).catch(() => {});
    void bridge.devices().then(setDevices).catch(() => {});
  }, [devicesOpen, locked]);
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

  async function startInvite() {
    try {
      const created = await bridge.startInvite();
      setInvite({ code: created.code });
    } catch (error) {
      setNotice(commandMessage(error, "An invitation could not be created"));
    }
  }

  async function answerInvite(accept: boolean) {
    try {
      await bridge.confirmInvite(accept);
      if (!accept) setInvite(null);
    } catch (error) {
      setNotice(commandMessage(error, "That pairing is no longer waiting"));
    }
  }

  async function cancelInvite() {
    await bridge.cancelInvite().catch(() => {});
    setInvite(null);
  }

  async function enableRecovery(recoveryKey: string) {
    try {
      await bridge.enableRecovery(recoveryKey);
      setRecoveryOn(true);
      setNotice("Recovery is on for this device");
    } catch (error) {
      setNotice(commandMessage(error, "Recovery could not be turned on"));
    }
  }

  async function syncNow() {
    try {
      await bridge.syncNow();
    } catch (error) {
      setNotice(commandMessage(error, "Sync could not start"));
    }
  }

  async function foundControlPlane() {
    try {
      await bridge.foundControlPlane();
      setDevices(await bridge.devices());
      setNotice("Device management is set up · invite your other device from here");
    } catch (error) {
      setNotice(commandMessage(error, "Device management could not be set up"));
    }
  }

  async function removeDevice(device: string) {
    try {
      await bridge.removeDevice(device);
      setDevices(await bridge.devices());
      setNotice("Removal accepted · the other devices are moving to a new key");
    } catch (error) {
      setNotice(commandMessage(error, "The device could not be removed"));
    }
  }

  async function cancelEnrollment() {
    try {
      await bridge.cancelEnrollment();
      setDevices(await bridge.devices());
      setNotice("Enrollment cancelled · that device received no key");
    } catch (error) {
      setNotice(commandMessage(error, "The enrollment could not be cancelled"));
    }
  }

  async function rejoined() {
    setDevices(await bridge.devices());
    setEntries(await bridge.listEntries());
    setNotice("Joined · this device kept its vault");
  }

  async function joined() {
    setVaultStatus("unlocked");
    setLocked(false);
    setEntries(await bridge.listEntries());
    setNotice("Joined · copying the vault from the other device");
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
        <div className="vault-chip"><div className="vault-emblem"><ShieldCheck size={16} /></div><div><strong>Personal vault</strong><span>{previewMode ? "Development preview · local only" : sync.state === "removed" ? "Removed from this vault" : sync.devices > 0 ? `Owner device · ${sync.devices + 1} devices` : "Owner device · local only"}</span></div><ChevronRight size={15} className="muted" /></div>
        <button className="new-item" onClick={() => { if (!locked) setEditor({ mode: "create" }); }} disabled={locked}><Plus size={17} /> New item <span>⌘ N</span></button>
        <nav className="nav-list" aria-label="Vault filters">
          <p className="nav-caption">YOUR VAULT <span>{entries.length}</span></p>
          {filters.map((item) => <button key={item} className={`nav-item ${filter === item ? "active" : ""}`} onClick={() => setFilter(item)}><span className={`nav-icon ${item === "Favorites" ? "star" : ""}`}>{item === "All items" ? "⌂" : item === "Favorites" ? "★" : item === "Logins" ? "↗" : "▤"}</span>{item}<span className="nav-count">{item === "All items" ? entries.length : item === "Favorites" ? entries.filter((e) => e.favorite).length : item === "Logins" ? entries.filter((e) => e.kind === "login").length : entries.filter((e) => e.kind === "secure_note").length}</span></button>)}
        </nav>
        <div className="sidebar-bottom"><button className="utility" onClick={() => setGeneratorOpen(true)}><Sparkles size={16} /> Generator</button><button className="utility"><Archive size={16} /> Archive</button><button className="utility"><Clock3 size={16} /> Activity</button><button className="utility"><MoreHorizontal size={16} /> Settings</button><button className="device-card" onClick={() => setDevicesOpen(true)} disabled={previewMode}><div className="device-icon"><Fingerprint size={18} /></div><div><strong>This device</strong><span>{previewMode ? "Preview data only" : sync.state === "removed" ? "Removed · tap for details" : sync.devices > 0 ? `Syncs with ${sync.devices} other ${sync.devices === 1 ? "device" : "devices"}` : "Only device · tap to add one"}</span></div><span className={`online-dot ${sync.state === "synced" || sync.state === "idle" ? "" : "offline-dot"}`} /></button></div>
      </aside>

      <section className="content-pane">
        <header className="topbar"><div className="breadcrumbs"><span>Personal vault</span><ChevronRight size={15} /><strong>{filter}</strong></div><div className="top-actions"><button className={`sync-status ${syncLabel(sync).tone}`} onClick={() => setDevicesOpen(true)} disabled={previewMode} title={sync.message ?? undefined}><span className="status-dot" />{syncLabel(sync).text}</button><button className="icon-button" title="Lock vault" onClick={lock}><LockKeyhole size={18} /></button><div className="avatar">YK</div></div></header>
        <div className="workspace">
          <div className="list-column">
            <div className="list-heading"><div><p className="eyebrow">{filter.toUpperCase()}</p><h1>{visible.length} <span>items</span></h1></div><button className="icon-button bordered" title="Import"><ArrowDownToLine size={17} /></button></div>
            <label className="search-box"><Search size={17} /><input aria-label="Search vault" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search your vault" /><kbd>⌘ K</kbd></label>
            <div className="entry-list">{visible.map((entry) => <button key={entry.id} className={`entry-row ${active?.id === entry.id ? "selected" : ""}`} onClick={() => setSelected(entry.id)}><div className={`entry-logo logo-${entry.kind}`}>{entry.kind === "secure_note" ? "▤" : entry.title.slice(0, 1)}</div><div className="entry-copy"><strong>{entry.title}</strong><span>{entry.username ?? "Secure note"}</span></div><div className="entry-meta">{entry.favorite && <span className="favorite">★</span>}<small>{entry.updatedAt}</small></div></button>)}{visible.length === 0 && <div className="empty-list"><Search size={22} /><strong>No matching items</strong><span>Try a different search or filter.</span></div>}</div>
          </div>
          <div className="detail-column">{locked && vaultStatus === "missing" && joining ? <JoinPanel onCancel={() => setJoining(false)} onJoined={() => void joined()} onNotice={setNotice} /> : locked ? <div className="empty-detail">{vaultStatus === "missing" ? <><Sparkles size={25} /><h2>Create your encrypted vault</h2><span>This device keeps its own vault. Choose a strong local password.</span></> : <><LockKeyhole size={25} /><h2>Vault locked</h2><span>{sync.pending > 0 ? `${sync.pending} received ${sync.pending === 1 ? "change is" : "changes are"} waiting to be verified when you unlock.` : "Unlock in the desktop window to view encrypted records."}</span></>}<div className="unlock-form"><input aria-label="Vault password" type="password" placeholder={vaultStatus === "missing" ? "New device password" : "Vault password"} value={unlockPassword} onChange={(event) => setUnlockPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void (vaultStatus === "missing" ? createVault() : unlock()); }} /><button onClick={() => void (vaultStatus === "missing" ? createVault() : unlock())}>{vaultStatus === "missing" ? <><Plus size={15} /> Create</> : <><UnlockKeyhole size={15} /> Unlock</>}</button></div>{vaultStatus === "missing" && !previewMode && <button className="link-button" onClick={() => setJoining(true)}>Join a vault from another device instead</button>}</div> : active ? <><div className="detail-head"><div className={`detail-logo logo-${active.kind}`}>{active.kind === "secure_note" ? "▤" : active.title.slice(0, 1)}</div><div className="detail-title"><div><h2>{active.title}</h2>{active.url && <span>{active.url}</span>}</div><button className="icon-button"><MoreHorizontal size={19} /></button></div></div><div className="detail-actions"><button onClick={() => void openEditor()}><span className="action-icon">✎</span> Edit</button><button onClick={copyTotp}><Copy size={15} /> Copy TOTP</button><button onClick={() => setNotice("Item link copied")}>Share <span className="action-arrow">↗</span></button></div><div className="record-card"><RecordField label="Username" value={active.username ?? "—"} /><RecordField label="Password" value="••••••••••••••" secret /><RecordField label="Website" value={active.url ?? "—"} link /></div><div className="history-note"><Clock3 size={15} /><div><strong>Revision history is retained</strong><span>Every edit keeps its signed parent revision.</span></div><ChevronRight size={15} /></div>{active.conflict && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Needs your decision</strong><span>Two signed revisions changed this item concurrently. Autofill is paused.</span></div><button className="conflict-action" onClick={() => void openReview()}>Review versions</button></div>}</> : <div className="empty-detail"><Sparkles size={25} /><h2>Select an item</h2><span>Your encrypted record will appear here after selection.</span></div>}</div>
        </div>
        {recoveryKey && !locked && <div className="recovery-overlay"><div className="recovery-card"><strong>Recovery key · store this offline</strong><code>{recoveryKey}</code><span>It will be cleared when you acknowledge it or the vault locks.</span><button onClick={() => setRecoveryKey(null)}>I stored it</button></div></div>}
        <footer className="footer-bar"><div><Wifi size={14} /><span>{previewMode ? "Development preview" : "Local vault"}</span><span className="footer-separator">•</span><span>{previewMode ? "No native sync session" : syncDetail(sync)}</span></div><button onClick={() => previewMode ? setNotice("Sync is unavailable in the browser preview") : setDevicesOpen(true)}>Devices <ChevronRight size={14} /></button></footer>
      </section>
      {generatorOpen && <div className="modal-backdrop" onClick={() => setGeneratorOpen(false)}><div className="generator-modal" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">TOOLS</p><h2>Password generator</h2></div><button className="icon-button" onClick={() => setGeneratorOpen(false)}><X size={18} /></button></div><Generator onCopy={(value) => { navigator.clipboard?.writeText(value); setNotice("Generated password copied"); }} /></div></div>}
      {editor && <div className="modal-backdrop" onClick={() => setEditor(null)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">{editor.mode === "edit" ? "EDIT ITEM" : "NEW ITEM"}</p><h2>{editor.mode === "edit" ? editor.detail.title : "Create an item"}</h2></div><button className="icon-button" onClick={() => setEditor(null)}><X size={18} /></button></div><EntryEditor detail={editor.mode === "edit" ? editor.detail : undefined} onCancel={() => setEditor(null)} onSave={saveEntry} /></div></div>}
      {review && <div className="modal-backdrop" onClick={() => setReview(null)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">RESOLVE CONFLICT</p><h2>{review.title}</h2></div><button className="icon-button" onClick={() => setReview(null)}><X size={18} /></button></div><p className="review-hint">These versions were changed independently. Keep one; it replaces all of them.</p><div className="version-list">{review.versions.map((version) => <div key={version.revision} className="version-card"><div className="version-meta"><strong>{version.thisDevice ? "This device" : `Device ${version.device}`}</strong><code>{version.revision.slice(0, 10)}</code></div>{version.deleted ? <span className="version-deleted">Deleted this item</span> : <dl><dt>Title</dt><dd>{version.title}</dd><dt>Username</dt><dd>{version.username || "—"}</dd><dt>Website</dt><dd>{version.url || "—"}</dd></dl>}<button className="generate-button" onClick={() => void keepVersion(version.revision)}>{version.deleted ? "Keep deletion" : "Keep this version"}</button></div>)}</div></div></div>}
      {devicesOpen && <div className="modal-backdrop" onClick={() => setDevicesOpen(false)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">DEVICES</p><h2>Devices and sync</h2></div><button className="icon-button" onClick={() => setDevicesOpen(false)}><X size={18} /></button></div>{!locked && !recoveryOn && <RecoveryPrompt onEnable={(key) => void enableRecovery(key)} />}<DevicesPanel sync={sync} devices={devices} invite={invite} locked={locked} onInvite={() => void startInvite()} onAnswer={(accept) => void answerInvite(accept)} onCancelInvite={() => void cancelInvite()} onSync={() => void syncNow()} onFound={() => void foundControlPlane()} onRemove={(device) => void removeDevice(device)} onCancelEnrollment={() => void cancelEnrollment()} onRejoined={() => void rejoined()} onNotice={setNotice} onCopy={(text) => { navigator.clipboard?.writeText(text); setNotice("Invitation copied · it works once"); }} /></div></div>}
      {notice && <div className="toast"><ShieldCheck size={15} />{notice}</div>}
    </main>
  );
}

function syncDetail(status: SyncStatus): string {
  if (status.state === "removed") return "This device was removed from the vault";
  if (status.state === "local") return "Only device";
  if (status.state === "error") return status.message ?? "Sync failed";
  if (status.state === "syncing") return "Syncing with your devices";
  if (status.lastSyncedAt) return `Last synced ${new Date(status.lastSyncedAt * 1000).toLocaleTimeString()}`;
  return "Not synced yet";
}

/** The first eight hex digits are enough to tell a handful of devices apart. */
function shortDevice(id: string): string {
  return id.slice(0, 8);
}

type DevicesPanelProps = {
  sync: SyncStatus;
  devices: DevicesInfo;
  invite: InviteState | null;
  locked: boolean;
  onInvite: () => void;
  onAnswer: (accept: boolean) => void;
  onCancelInvite: () => void;
  onSync: () => void;
  onFound: () => void;
  onRemove: (device: string) => void;
  onCancelEnrollment: () => void;
  onRejoined: () => void;
  onNotice: (text: string) => void;
  onCopy: (text: string) => void;
};

function DevicesPanel({ sync, devices, invite, locked, onInvite, onAnswer, onCancelInvite, onSync, onFound, onRemove, onCancelEnrollment, onRejoined, onNotice, onCopy }: DevicesPanelProps) {
  const [removing, setRemoving] = useState<string | null>(null);
  const [rejoining, setRejoining] = useState(false);

  if (devices.setup === "removed") {
    return <div className="device-panel">
      <div className="conflict-banner"><CircleAlert size={16} /><div><strong>This device was removed from the vault</strong><span>Your other devices moved to a new key that this device never received. It gets no further changes, and nothing it writes is accepted by them. What it already held stays readable here.</span></div></div>
    </div>;
  }
  if (invite?.sas) {
    return <div className="device-panel">
      <p className="review-hint">Compare this code with the one on the other device. Confirm only if they are identical.</p>
      <div className="sas-code">{invite.sas}</div>
      <div className="form-actions"><button className="secondary" onClick={() => onAnswer(false)}>They differ</button><button className="generate-button" onClick={() => onAnswer(true)}>Codes match</button></div>
    </div>;
  }
  if (invite) {
    return <div className="device-panel">
      <p className="review-hint">On the other device, choose “Join a vault from another device” and paste this invitation. It works once and expires in 15 minutes.</p>
      <div className="generated-value"><code>{invite.code}</code><button onClick={() => onCopy(invite.code)} title="Copy invitation"><Copy size={16} /></button></div>
      <p className="review-hint">Waiting for the other device…</p>
      <div className="form-actions"><button className="secondary" onClick={onCancelInvite}>Cancel</button></div>
    </div>;
  }
  if (devices.setup === "paired-before") {
    if (rejoining) return <JoinPanel keepsVault onCancel={() => setRejoining(false)} onJoined={() => { setRejoining(false); onRejoined(); }} onNotice={onNotice} />;
    return <div className="device-panel">
      <p className="review-hint">This device was paired by an earlier version. Your devices now agree together on which devices belong to the vault, so that a lost one can be removed. Set that up on one of the two devices only, then invite the other from it. Both keep their vaults.</p>
      <button className="generate-button" onClick={onFound} disabled={locked}>{locked ? "Unlock to continue" : "Set it up on this device"}</button>
      <button className="secondary" onClick={() => setRejoining(true)} disabled={locked}>I set it up on the other device · join with an invitation</button>
    </div>;
  }
  if (devices.setup === "joining") {
    return <div className="device-panel"><p className="review-hint">This device is joining a vault. It becomes a member once the vault's devices have enrolled it.</p></div>;
  }
  if (devices.setup !== "ready") {
    return <div className="device-panel"><p className="review-hint">{locked ? "Unlock the vault to set up its devices." : "Devices are being set up…"}</p></div>;
  }

  const others = devices.members.filter((member) => !member.thisDevice);
  const pending = devices.pending;
  return <div className="device-panel">
    {devices.members.map((member) => <div key={member.id} className="peer-row">
      <div className="device-icon"><Fingerprint size={18} /></div>
      <div><strong>{member.thisDevice ? "This device" : `Device ${shortDevice(member.id)}`}</strong><span>{member.thisDevice ? shortDevice(member.id) : member.address ?? "Address not known yet"}</span></div>
      {!member.thisDevice && !pending && (removing === member.id
        ? <div className="form-actions"><button className="secondary" onClick={() => setRemoving(null)}>Keep</button><button className="generate-button" onClick={() => { setRemoving(null); onRemove(member.id); }}>Remove</button></div>
        : <button className="secondary" disabled={locked} onClick={() => setRemoving(member.id)}>Remove…</button>)}
    </div>)}
    {removing && <p className="review-hint">Removing a device moves the others to a new key that it never receives. It keeps what it already had, so change any passwords it could have seen. This cannot be undone.</p>}
    {pending && pending.kind === "enroll" && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>{pending.cancelled ? "Cancelling an enrollment" : `Device ${shortDevice(pending.device)} is joining`}</strong><span>{pending.cancelled ? "Your devices are undoing it." : "It becomes a member once it has caught up. Until then no other device can be added or removed. If it never finishes, cancel it; it has received no key."}</span></div>{!pending.cancelled && <button className="conflict-action" disabled={locked} onClick={onCancelEnrollment}>Cancel enrollment</button>}</div>}
    {pending && pending.kind === "remove" && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Removing device {shortDevice(pending.device)}</strong><span>Waiting for the remaining devices. The new key takes effect only when they have all agreed; bring them online to finish.</span></div></div>}
    <p className="review-hint">{syncDetail(sync)}{sync.pending > 0 ? ` · ${sync.pending} waiting for unlock` : ""}</p>
    <p className="review-hint">{quorumHint(devices)}</p>
    <div className="form-actions">
      {others.length > 0 && <button className="secondary" onClick={onSync} disabled={sync.state === "syncing"}>Sync now</button>}
      <button className="generate-button" onClick={onInvite} disabled={locked || Boolean(pending)}>{locked ? "Unlock to invite a device" : "Invite a device"}</button>
    </div>
  </div>;
}

/** Says how many devices a change needs, in terms the owner can act on. */
function quorumHint(devices: DevicesInfo): string {
  const count = devices.members.length;
  if (count <= 1) return "Each device keeps a full encrypted copy and they sync directly, with no server. You will compare a six-digit code on both screens.";
  if (count === 2) return "Adding or removing a device needs both of these devices online. With three or more, one can be away or lost and still be removed.";
  return `Adding or removing a device needs ${devices.quorum} of these ${count} devices online. A locked device still counts while its app is open.`;
}

/** A device that joined from another one has its own root key, so the
 * recovery key must be entered once before it can unlock this device. */
function RecoveryPrompt({ onEnable }: { onEnable: (recoveryKey: string) => void }) {
  const [recoveryKey, setRecoveryKey] = useState("");
  return <div className="device-panel recovery-prompt">
    <p className="review-hint">Recovery is off on this device. Enter the vault's recovery key once so a forgotten password can be recovered here too. It is checked before it is accepted.</p>
    <div className="unlock-form"><input aria-label="Recovery key" type="password" placeholder="OSM-RK1-…" value={recoveryKey} onChange={(event) => setRecoveryKey(event.target.value)} /><button disabled={!recoveryKey.trim()} onClick={() => { onEnable(recoveryKey); setRecoveryKey(""); }}>Turn on</button></div>
  </div>;
}

/** Joins a vault from an invitation. With `keepsVault`, this device already
 * holds the vault and only joins its devices, so no new password is asked. */
function JoinPanel({ keepsVault, onCancel, onJoined, onNotice }: { keepsVault?: boolean; onCancel: () => void; onJoined: () => void; onNotice: (text: string) => void }) {
  const [code, setCode] = useState("");
  const [sas, setSas] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [waiting, setWaiting] = useState(false);

  async function connect() {
    try {
      setSas((await bridge.joinStart(code.trim())).sas);
    } catch (error) {
      onNotice(commandMessage(error, "Could not reach the inviting device"));
    }
  }

  async function finish() {
    if (!keepsVault && password.length < 12) { onNotice("Use at least 12 characters for this device password"); return; }
    setWaiting(true);
    try {
      // Resolves once the owner also confirms on the inviting device and
      // the vault's devices have enrolled this one.
      await bridge.joinFinish(keepsVault ? undefined : password);
      setPassword("");
      onJoined();
    } catch (error) {
      setWaiting(false);
      setSas(null);
      onNotice(commandMessage(error, "Joining did not complete"));
    }
  }

  async function cancel() {
    await bridge.cancelJoin().catch(() => {});
    onCancel();
  }

  if (!sas) {
    return <div className="empty-detail">
      <Fingerprint size={25} /><h2>{keepsVault ? "Join your other device" : "Join an existing vault"}</h2>
      <span>On your other device, open Devices and choose Invite a device. Paste the invitation here.</span>
      <textarea className="join-code" aria-label="Invitation" rows={4} value={code} onChange={(event) => setCode(event.target.value)} placeholder="OSM-PAIR1-…" />
      <div className="form-actions join-actions"><button className="secondary" onClick={() => void cancel()}>Cancel</button><button className="generate-button" disabled={!code.trim()} onClick={() => void connect()}>Continue</button></div>
    </div>;
  }
  return <div className="empty-detail">
    <ShieldCheck size={25} /><h2>Compare the codes</h2>
    <span>The other device shows a code too. Continue only if they are identical.</span>
    <div className="sas-code">{sas}</div>
    {!keepsVault && <div className="unlock-form"><input aria-label="New device password" type="password" placeholder="New password for this device" value={password} disabled={waiting} onChange={(event) => setPassword(event.target.value)} /></div>}
    <div className="form-actions join-actions"><button className="secondary" disabled={waiting} onClick={() => void cancel()}>They differ</button><button className="generate-button" disabled={waiting || (!keepsVault && !password)} onClick={() => void finish()}>{waiting ? "Waiting for your other devices…" : "Codes match · join"}</button></div>
  </div>;
}

function RecordField({ label, value, secret, link }: { label: string; value: string; secret?: boolean; link?: boolean }) {
  return <div className="record-field"><label>{label}</label><div><span className={secret ? "masked" : link ? "record-link" : ""}>{value}</span>{secret ? <button className="field-action" onClick={() => navigator.clipboard?.writeText(value)}> <Copy size={14} /> </button> : link ? <span className="external">↗</span> : null}</div></div>;
}

function commandMessage(error: unknown, fallback: string): string {
  const code = (error as { code?: string } | null)?.code;
  if (code === "conflict") return "This item changed since you opened it · reopen to edit";
  if (code === "unresolved") return "This item has conflicting versions · review them first";
  if (code === "not_confirmed") return "The pairing was declined";
  if (code === "pin_mismatch") return "That device is not the one in the invitation";
  if (code === "invitation_expired") return "The invitation has expired · create a new one";
  if (code === "invalid_invitation") return "That is not a valid invitation";
  if (code === "quorum_unavailable") return "Not enough of your devices are reachable · most of them must be online to add or remove one · nothing was changed";
  if (code === "removed") return "This device was removed from the vault";
  if (code === "change_in_progress") return "Another device is still being added or removed · finish or cancel that first";
  if (code === "enrollment_refused") return "Your other devices did not accept this device";
  if (code === "enrollment_timeout") return "This device was not enrolled in time · cancel it on the inviting device and try again";
  if (code === "vault_mismatch") return "That invitation is for a different vault";
  if (code === "vault_exists" || code === "already_managed") return "This device already belongs to a vault's devices";
  if (code === "rejected") return `${fallback} · ${(error as { message?: string }).message ?? "your devices refused it"}`;
  if (code === "invalid_recovery_key") return "That is not this vault's recovery key";
  if (code === "upgrade_requires_password") return "Unlock with your password once to upgrade this vault";
  if (code === "network" || code === "timeout") return `${fallback} · ${(error as { message?: string }).message ?? "network error"}`;
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
