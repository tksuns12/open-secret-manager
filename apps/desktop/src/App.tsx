import { useEffect, useMemo, useRef, useState } from "react";
import { Archive, ArrowDownToLine, ChevronRight, HardDriveDownload, CircleAlert, Clock3, Copy, Eraser, Eye, EyeOff, Fingerprint, Globe, KeyRound, LockKeyhole, Plus, Search, Settings as SettingsIcon, ShieldCheck, SlidersHorizontal, Sparkles, Trash2, UnlockKeyhole, Wifi, X } from "lucide-react";
import { bridge, hasNativeBridge, previewHasDevices } from "./bridge";
import { BrandMark } from "./BrandMark";
import { cardBrand, cardDigits, passesCardCheck } from "./card";
import type { ArchivedItem, ArchiveInfo, BackupAge, BrowserInfo, BrowserStatus, CardFieldName, DeletedEntry, DevicesInfo, EntryDetail, EntryInput, EntryKind, FillAsked, FillCardChoice, FillLogin, GeneratorChoice, HeldChange, HistoryEntry, ImportFormat, ImportSummary, InviteQr, MemberInfo, PasskeyAsked, PasskeyChoice, PasskeySummary, Restored, SavedBackup, SyncState, SyncStatus, VaultEntry, VersionSummary } from "./types";

const filters = ["All items", "Favorites", "Logins", "Cards", "Secure notes"] as const;
/** The sign before each filter in the sidebar. */
const FILTER_ICONS = { "All items": "⌂", Favorites: "★", Logins: "↗", Cards: "▭", "Secure notes": "▤" } as const;
/** How long without input in the window locks the vault, as the owner may set it. */
const AUTO_LOCK_CHOICES = [1, 5, 15, 60, 240];
function minutesText(minutes: number): string {
  return minutes === 1 ? "a minute" : minutes === 60 ? "an hour" : minutes % 60 === 0 ? `${minutes / 60} hours` : `${minutes} minutes`;
}
/** What an item of a kind is called where it has no username to show. */
function kindLabel(kind: EntryKind): string {
  return kind === "secure_note" ? "Secure note" : kind === "identity" ? "Identity" : kind === "card" ? "Card" : "Login";
}
/** The line under an item's title in the list: a card's brand and the last four digits of its number, or else the username, and a login's passkeys. */
function subtitle(entry: VaultEntry): string {
  if (entry.kind === "card") return [entry.brand || "Card", entry.cardEnding ? `•••• ${entry.cardEnding}` : ""].filter(Boolean).join(" ");
  const passkeys = !entry.passkeys ? "" : entry.passkeys === 1 ? "passkey" : `${entry.passkeys} passkeys`;
  return [entry.username || kindLabel(entry.kind), passkeys].filter(Boolean).join(" · ");
}
/** Why the system said the owner's session went away from the app. */
const AWAY: Record<string, string> = {
  sleep: "the computer went to sleep",
  screens_sleep: "the displays went to sleep",
  screen_locked: "the screen locked",
  screen_saver: "the screen saver started",
  switched_out: "another user took the screen",
};
type Filter = (typeof filters)[number];
function inFilter(entry: VaultEntry, filter: Filter): boolean {
  switch (filter) {
    case "All items": return true;
    case "Favorites": return Boolean(entry.favorite);
    case "Logins": return entry.kind === "login";
    case "Cards": return entry.kind === "card";
    case "Secure notes": return entry.kind === "secure_note";
  }
}
type EditorState = { mode: "create" } | { mode: "edit"; detail: EntryDetail };
type ReviewState = { id: string; title: string; versions: VersionSummary[] };
/** An invitation waiting for the other device, for one that votes or not. */
type InviteState = { code: string; votes: boolean; qr: InviteQr; sas?: string };

/** Topbar wording and colour for each sync state. */
function syncLabel(status: SyncStatus): { tone: SyncState; text: string } {
  if (status.replaced.length > 0 && status.state !== "syncing") return { tone: "offline", text: "A device changed · see Devices" };
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
  // Whether the last unlock found records taken out of the vault's file.
  const [rowsChanged, setRowsChanged] = useState(false);
  const [backupAge, setBackupAge] = useState<BackupAge | null>(null);
  const [previewMode] = useState(() => !hasNativeBridge());
  // The preview has devices to show only when its address asks.
  const devicesUnavailable = previewMode && !previewHasDevices();
  const [selected, setSelected] = useState("1");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("All items");
  const [sync, setSync] = useState<SyncStatus>({ state: "local", devices: 0, pending: 0, replaced: [] });
  const [devices, setDevices] = useState<DevicesInfo>({ setup: "none", members: [], epoch: 0, quorum: 0 });
  const [devicesOpen, setDevicesOpen] = useState(false);
  const [invite, setInvite] = useState<InviteState | null>(null);
  const [joining, setJoining] = useState(false);
  // The empty-vault screen restores a backup; the lock screen sets a new
  // password with the recovery key.
  const [restoring, setRestoring] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [backupOpen, setBackupOpen] = useState(false);
  // Why the vault file here cannot be opened, when one is here and cannot.
  const [vaultProblem, setVaultProblem] = useState<string | null>(null);
  const [recoveryOn, setRecoveryOn] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [review, setReview] = useState<ReviewState | null>(null);
  const [held, setHeld] = useState<HeldChange[]>([]);
  const [heldOpen, setHeldOpen] = useState(false);
  const [archivesOpen, setArchivesOpen] = useState(false);
  const [browserOpen, setBrowserOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  // An item's history, while it is open.
  const [history, setHistory] = useState<{ id: string; title: string; versions: HistoryEntry[] } | null>(null);
  // The items deleted, while that list is open.
  const [deleted, setDeleted] = useState<DeletedEntry[] | null>(null);
  // The owner's auto-lock setting, in minutes.
  const [autoLockMinutes, setAutoLockMinutes] = useState(5);
  /** The generator's choice kept on this device, once read. */
  const [generator, setGenerator] = useState<GeneratorChoice | null>(null);
  const autoLockRef = useRef(autoLockMinutes);
  // When the vault locks for want of activity, by the clock. Hidden or
  // covered, the window leaves the vault unlocked for that time as well, but
  // its timers can run late then: it hands the rest of the time to the
  // native side, which locks on time, and its coming back and a browser's
  // request check the clock first.
  const lockDue = useRef(Infinity);
  // The open item's details: its notes and which secrets it has.
  const [shown, setShown] = useState<EntryDetail | null>(null);
  // A request from a browser extension that waits for a decision here.
  const [fill, setFill] = useState<FillAsked | null>(null);
  // The request last seen waiting, and the one decided in this window, so
  // that one which ends on its own can be told apart.
  const fillSeen = useRef<string | null>(null);
  const fillDecided = useRef<string | null>(null);
  // A device joining with the vault it has must stay unlocked to finish.
  const [rejoining, setRejoining] = useState(false);
  // Pairing sends the owner to another device or window, for no longer
  // than the time without activity: the lock then ends it.
  const pairing = Boolean(invite) || rejoining;
  const pairingRef = useRef(pairing);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void bridge.vaultProblem().then(setVaultProblem).catch(() => {});
    void bridge.status().then(async (status) => {
      setVaultStatus(status);
      setLocked(status !== "unlocked");
      if (status === "unlocked") setEntries(await bridge.listEntries());
    }).catch(() => { setVaultStatus("missing"); setLocked(true); });
  }, []);
  // Each unlock checks the vault's file; what it found is said here, however it was unlocked.
  useEffect(() => {
    if (locked) { setRowsChanged(false); return; }
    void bridge.rowsChanged().then(setRowsChanged).catch(() => {});
  }, [locked]);
  // How long since this computer last saved a backup: read at each unlock and after each backup.
  const loadBackupAge = () => { void bridge.backupAge().then(setBackupAge).catch(() => {}); };
  useEffect(() => {
    if (locked) { setBackupAge(null); return; }
    loadBackupAge();
  }, [locked]);
  useEffect(() => {
    void bridge.syncStatus().then(setSync).catch(() => {});
    const loadDevices = () => { void bridge.devices().then(setDevices).catch(() => {}); };
    loadDevices();
    loadFill();
    const subscriptions = [
      // A request arrived from a browser, or the one waiting ended.
      bridge.listen("fill-request", () => {
        const locking = lockIfDue();
        if (locking) void locking.then(loadFill, loadFill); else loadFill();
      }),
      bridge.listen<SyncStatus>("sync-status", setSync),
      bridge.listen("devices-changed", loadDevices),
      // This device's copy of the vault was put away, because it learned
      // that it was removed or because the owner asked for it here: it is a
      // device without a vault again.
      bridge.listen<string>("device-reset", () => {
        setEntries([]); setLocked(true); setVaultStatus("missing"); setRecoveryKey(null); setEditor(null); setReview(null); setHeldOpen(false); setArchivesOpen(false);
        setInvite(null); setRejoining(false); setJoining(false); setDevicesOpen(false);
        void bridge.devices().then((info) => {
          setDevices(info);
          setNotice(info.resetReason === "left" ? "This device's copy was moved to an archive folder · join the new vault with an invitation" : "This device was removed from the vault · its copy was moved to an archive folder");
        }).catch(() => {});
      }),
      // A sync merged revisions: reload the list if the vault is readable.
      bridge.listen("vault-changed", () => {
        void bridge.status().then(async (status) => { if (status === "unlocked") setEntries(await bridge.listEntries()); });
      }),
      // The system said the owner's session went away, and the app locked.
      // A pairing needs the owner here, so it ends too.
      bridge.listen<string>("vault-locked", (reason) => {
        if (reason === "idle") { showIdleLocked(); return; }
        showLocked();
        const cancelled = endPairing();
        setNotice(`Vault locked because ${AWAY[reason] ?? "the session went away"}${cancelled ? " · the pairing was cancelled" : ""}`);
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
  function loadFill() { void bridge.fillRequest().then(setFill).catch(() => {}); }
  // The logins for a waiting request are listed only while the vault is
  // unlocked, so locking and unlocking both change what is shown.
  useEffect(loadFill, [locked]);
  useEffect(() => {
    const before = fillSeen.current;
    const now = fill?.requestId ?? null;
    fillSeen.current = now;
    if (before && before !== now && fillDecided.current !== before) setNotice("The browser stopped waiting · nothing was sent");
  }, [fill]);
  /** A locked vault cannot finish a pairing, so locking ends one in progress. */
  function endPairing() {
    if (!pairingRef.current) return false;
    void bridge.cancelInvite().catch(() => {});
    void bridge.cancelJoin().catch(() => {});
    setInvite(null);
    setRejoining(false);
    return true;
  }
  function showLocked() {
    setEntries([]); setLocked(true); setRecoveryKey(null); setEditor(null); setReview(null); setHeldOpen(false); setArchivesOpen(false); setImportOpen(false); setShown(null); setHistory(null); setDeleted(null);
  }
  /** A lock for want of activity, which says nothing unless it ends a pairing. */
  function showIdleLocked() {
    lockDue.current = Infinity;
    showLocked();
    if (endPairing()) setNotice(`Vault locked after ${minutesText(autoLockRef.current)} without activity · the pairing was cancelled`);
  }
  function lockQuietly() {
    const locking = bridge.lock();
    showIdleLocked();
    return locking;
  }
  /** Locks if the time without activity has run out, as the timer, late, would have. */
  function lockIfDue() {
    return Date.now() >= lockDue.current ? lockQuietly() : null;
  }
  useEffect(() => {
    void bridge.settings().then((settings) => { setAutoLockMinutes(settings.autoLockMinutes); setGenerator(settings.generator); }).catch(() => {});
  }, []);
  useEffect(() => {
    autoLockRef.current = autoLockMinutes;
    const wait = autoLockMinutes * 60 * 1000;
    let timer = 0;
    const reset = () => {
      window.clearTimeout(timer); lockDue.current = Date.now() + wait; timer = window.setTimeout(lockQuietly, wait);
      // Input while hidden, should a system give it: the native side's time starts again too.
      if (document.visibilityState === "hidden") void bridge.lockWhenIdle(wait).catch(() => {});
    };
    // Only input counts as activity: not the window being shown again, which
    // a browser's request does too.
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        if (Number.isFinite(lockDue.current)) void bridge.lockWhenIdle(Math.max(0, lockDue.current - Date.now())).catch(() => {});
        return;
      }
      void bridge.lockWhenIdle(null).catch(() => {});
      lockIfDue();
    };
    reset();
    for (const event of ["pointerdown", "keydown", "touchstart"]) window.addEventListener(event, reset, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    return () => { window.clearTimeout(timer); for (const event of ["pointerdown", "keydown", "touchstart"]) window.removeEventListener(event, reset); document.removeEventListener("visibilitychange", onVisibility); };
  }, [autoLockMinutes]);
  useEffect(() => { pairingRef.current = pairing; }, [pairing]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "n" && !locked) { event.preventDefault(); setEditor({ mode: "create" }); }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k" && !locked) { event.preventDefault(); searchRef.current?.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [locked]);
  useEffect(() => {
    if (!devicesOpen) return;
    void bridge.recoveryStatus().then(setRecoveryOn).catch(() => {});
    void bridge.devices().then(setDevices).catch(() => {});
  }, [devicesOpen, locked]);
  // Held changes are read with the vault. A sync can add to them, and a
  // decision made on another device settles them here; both reload the list.
  // The preview has some only when its address asks.
  useEffect(() => {
    if (locked) { setHeld([]); return; }
    void bridge.listHeld().then(setHeld).catch(() => setHeld([]));
  }, [locked, entries]);
  // Something else answers where one of the vault's devices used to: most
  // likely that device started over as a new vault and this one was left
  // behind. The owner is told once; the Devices panel says what to do.
  const deviceReplaced = sync.replaced.length > 0;
  useEffect(() => {
    if (deviceReplaced) setNotice("One of your devices answers as a different device · open Devices");
  }, [deviceReplaced]);
  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 3200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const visible = useMemo(() => entries.filter((entry) => {
    const matchesQuery = `${entry.title} ${entry.username ?? ""} ${entry.url ?? ""} ${entry.brand ?? ""}`.toLowerCase().includes(query.toLowerCase());
    return matchesQuery && inFilter(entry, filter);
  }), [entries, filter, query]);
  const active = entries.find((entry) => entry.id === selected) ?? visible[0];
  // The open item's details, read again when it changes.
  useEffect(() => {
    if (!active || locked) { setShown(null); return; }
    let current = true;
    void bridge.getEntry(active.id).then((detail) => { if (current) setShown(detail); }).catch(() => { if (current) setShown(null); });
    return () => { current = false; };
  }, [active?.id, active?.revision, locked]);

  /** Copies a secret of the open item through the shell, which clears it after 30 seconds. */
  async function copySecret(what: "password" | "code" | "field", name = "") {
    if (!active) return;
    if (previewMode) {
      setNotice("Copying is not available in the browser preview");
      return;
    }
    try {
      if (what === "password") await bridge.copyPassword(active.id);
      else if (what === "code") await bridge.copyTotp(active.id);
      else await bridge.copyField(active.id, name);
      setNotice(`${what === "password" ? "Password" : what === "code" ? "One-time code" : name} copied · cleared in 30 seconds`);
    } catch (error) {
      setNotice(commandMessage(error, "Nothing was copied"));
    }
  }

  async function openHistory() {
    if (!active) return;
    try {
      setHistory({ id: active.id, title: active.title, versions: await bridge.itemHistory(active.id) });
    } catch (error) {
      setNotice(commandMessage(error, "The history could not be read"));
    }
  }

  async function openDeleted() {
    try {
      setDeleted(await bridge.deletedEntries());
    } catch (error) {
      setNotice(commandMessage(error, "The deleted items could not be read"));
    }
  }

  /** Brings back a version of an item; `heads` are the current versions the owner was shown. */
  async function restore(id: string, revision: string, heads: string[], what: string) {
    try {
      const restored = await bridge.restoreEntry(id, revision, heads);
      setEntries(await bridge.listEntries());
      setSelected(restored.id);
      setHistory(null);
      setDeleted(null);
      setNotice(`${what} · on all your devices at the next sync`);
    } catch (error) {
      setNotice(commandMessage(error, "It could not be restored"));
    }
  }

  // Only the last choice's reply is shown: an earlier one that arrives
  // after a later click would put the box back, and the next click would
  // build on that.
  const generatorCalls = useRef(0);
  async function changeGenerator(choice: GeneratorChoice) {
    const call = ++generatorCalls.current;
    setGenerator(choice);
    try {
      const saved = (await bridge.setGenerator(choice)).generator;
      if (call === generatorCalls.current) setGenerator(saved);
    } catch (error) {
      setNotice(commandMessage(error, "The generator's choice was not saved"));
    }
  }

  async function copyGenerated(value: string) {
    if (previewMode) {
      setNotice("Copying is not available in the browser preview");
      return;
    }
    try {
      await bridge.copyGenerated(value);
      setNotice("Generated password copied · cleared in 30 seconds");
    } catch (error) {
      setNotice(commandMessage(error, "Nothing was copied"));
    }
  }

  async function changeAutoLock(minutes: number) {
    try {
      const settings = await bridge.setAutoLock(minutes);
      setAutoLockMinutes(settings.autoLockMinutes);
      setNotice(`The vault locks after ${minutesText(settings.autoLockMinutes)} without activity`);
    } catch (error) {
      setNotice(commandMessage(error, "The setting was not saved"));
    }
  }

  async function imported(added: number) {
    setImportOpen(false);
    setEntries(await bridge.listEntries().catch(() => entries));
    setNotice(`${added} ${added === 1 ? "item" : "items"} imported`);
  }

  function closeImport() {
    setImportOpen(false);
    void bridge.cancelImport().catch(() => {});
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

  async function decideHeld(change: HeldChange, keep: boolean) {
    try {
      if (keep) await bridge.acceptHeld(change.revision);
      else await bridge.discardHeld(change.revision);
      // Reloading the items reloads what is still held.
      setEntries(await bridge.listEntries());
      const follows = change.removedDevice && sync.devices > 0 ? " · your other devices follow at the next sync" : "";
      setNotice(keep ? `Change kept${follows}` : `Change rejected${follows}`);
    } catch (error) {
      // Settled meanwhile, here or by a decision made on another device.
      const settled = (error as { code?: string } | null)?.code === "not_found";
      if (settled) setEntries(await bridge.listEntries().catch(() => entries));
      setNotice(settled ? "That change was already settled" : commandMessage(error, "That change could not be settled"));
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

  async function removePasskey(credentialId: string) {
    if (!shown) return;
    try {
      await bridge.removePasskey(shown.id, shown.revision, credentialId);
      setEntries(await bridge.listEntries());
      setNotice("Passkey removed");
    } catch (error) {
      setNotice(commandMessage(error, "The passkey could not be removed"));
    }
  }

  async function deleteEntry() {
    if (editor?.mode !== "edit") return;
    try {
      await bridge.deleteEntry(editor.detail.id, editor.detail.revision);
      setEntries(await bridge.listEntries());
      setSelected("");
      setEditor(null);
      setNotice("Item deleted");
    } catch (error) {
      setNotice(commandMessage(error, "The item could not be deleted"));
    }
  }

  async function startInvite(votes: boolean) {
    try {
      const created = await bridge.startInvite(votes);
      setInvite({ code: created.code, votes, qr: created.qr });
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

  async function recovered(recoveryKey: string, summary: string) {
    setDevices(await bridge.devices());
    setEntries(await bridge.listEntries());
    setLocked(false);
    setVaultStatus("unlocked");
    setDevicesOpen(false);
    setRecoveryKey(recoveryKey);
    setNotice(summary);
  }

  async function restored(result: Restored) {
    setRestoring(false);
    const carried = `${result.items} ${result.items === 1 ? "item" : "items"}`;
    const conflicts = result.conflicts > 0 ? ` · ${result.conflicts} still need your decision` : "";
    const held = result.heldLeftBehind > 0 ? ` · ${result.heldLeftBehind} held for review stayed in the archived copy` : "";
    await recovered(result.recoveryKey, `Backup restored as a new vault · ${carried}${conflicts}${held} · the backup with its history is in the Archive`);
  }

  async function putUnreadableAway() {
    try {
      const archive = await bridge.putUnreadableAway();
      setVaultProblem(null);
      setNotice(`The vault file was moved to ${archive} · nothing was deleted`);
    } catch (error) {
      if ((error as { code?: string } | null)?.code === "opened") {
        setVaultProblem(null);
        setVaultStatus("locked");
        setNotice("The vault file opens now · unlock it");
      } else {
        setNotice(commandMessage(error, "The vault file could not be moved"));
      }
    }
  }

  async function passwordReset() {
    setResetting(false);
    setEntries(await bridge.listEntries());
    setLocked(false);
    setVaultStatus("unlocked");
    const unconfirmed = await bridge.pendingRecoveryKey().catch(() => null);
    if (unconfirmed) setRecoveryKey(unconfirmed);
    setNotice("New password set · the vault is unlocked");
  }

  async function resetDevice() {
    try {
      await bridge.resetDevice();
      setEntries([]);
      setLocked(true);
      setVaultStatus("missing");
      setJoining(true);
      setDevicesOpen(false);
      setDevices(await bridge.devices());
      setNotice("This device was reset · its old copy is in an archive folder · join again with an invitation");
    } catch (error) {
      setNotice(commandMessage(error, "This device could not be reset"));
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

  async function sendFill(login: FillLogin) {
    if (!fill?.session) return;
    fillDecided.current = fill.requestId;
    try {
      await bridge.approveFill(fill.requestId, login.id, fill.session);
      setFill(null);
      setNotice(`${login.title} was sent to the page · the form was not submitted`);
    } catch (error) {
      fillDecided.current = null;
      const code = (error as { code?: string } | null)?.code;
      setNotice(code === "locked" ? "The vault locked before the login was sent · unlock and choose again"
        : code === "fill_ended" ? "The browser no longer waits for this · nothing was sent"
        : code === "not_for_this_page" ? "That item is not a login for this page · nothing was sent"
        : commandMessage(error, "The login could not be sent"));
      loadFill();
    }
  }

  async function sendCard(card: FillCardChoice) {
    if (!fill?.session) return;
    fillDecided.current = fill.requestId;
    try {
      await bridge.approveCard(fill.requestId, card.id, fill.session);
      setFill(null);
      setNotice(`${card.title} was sent to the page · the form was not submitted`);
    } catch (error) {
      fillDecided.current = null;
      const code = (error as { code?: string } | null)?.code;
      setNotice(code === "locked" ? "The vault locked before the card was sent · unlock and choose again"
        : code === "fill_ended" ? "The browser no longer waits for this · nothing was sent"
        : code === "not_a_card" ? "That card cannot be filled · nothing was sent"
        : commandMessage(error, "The card could not be sent"));
      loadFill();
    }
  }

  async function sendPasskey(choice: PasskeyChoice) {
    if (!fill?.session || !fill.passkey) return;
    const asked = fill.passkey;
    fillDecided.current = fill.requestId;
    try {
      await bridge.approvePasskey(fill.requestId, fill.session, choice);
      setFill(null);
      setNotice(asked.ceremony === "create" ? `A passkey for ${asked.rpId} was saved and sent to the page` : `You were signed in to ${asked.rpId} with your passkey`);
    } catch (error) {
      fillDecided.current = null;
      const code = (error as { code?: string } | null)?.code;
      if (code === "passkey_exists") { fillDecided.current = fill.requestId; setFill(null); }
      setNotice(code === "locked" ? "The vault locked before the passkey was sent · unlock and choose again"
        : code === "fill_ended" ? "The browser no longer waits for this · nothing was sent"
        : code === "not_verified" ? "You were not verified · nothing was sent"
        : code === "wrong_password" ? "That is not this device's password · nothing was sent"
        : code === "passkey_exists" ? `${asked.rpId} already has a passkey of yours for this account · nothing new was made`
        : code === "not_for_this_page" ? "That is not for this site · nothing was sent"
        : commandMessage(error, "The passkey could not be sent"));
      if (code !== "passkey_exists") loadFill();
    }
  }

  async function useBrowserPasskey() {
    if (!fill) return;
    fillDecided.current = fill.requestId;
    await bridge.useBrowserPasskey(fill.requestId).catch(() => {});
    setFill(null);
    setNotice("The browser's own passkeys answer the page instead");
  }

  async function denyFill() {
    if (!fill) return;
    fillDecided.current = fill.requestId;
    await bridge.denyFill(fill.requestId).catch(() => {});
    setFill(null);
    setNotice("Request denied · nothing was sent");
  }

  async function lock() {
    await bridge.lock();
    setEntries([]);
    setLocked(true);
    setRecoveryKey(null);
    setEditor(null);
    setReview(null);
    setHeldOpen(false);
    setArchivesOpen(false);
    setNotice(endPairing() ? "Vault locked · the pairing was cancelled" : "Vault locked");
  }

  async function unlock() {
    if (!unlockPassword) return;
    try {
      await bridge.unlock(unlockPassword);
      setUnlockPassword("");
      setEntries(await bridge.listEntries());
      setLocked(false);
      setVaultStatus("unlocked");
      // A recovery key the owner never confirmed storing is shown again.
      const unconfirmed = await bridge.pendingRecoveryKey().catch(() => null);
      if (unconfirmed) setRecoveryKey(unconfirmed);
      setNotice(unconfirmed ? "Vault unlocked · store the recovery key shown here" : "Vault unlocked");
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
        <div className="brand"><div className="brand-mark"><BrandMark size={27} /></div><span>open secret</span><span className="brand-dot">·</span></div>
        <div className="vault-chip"><div className="vault-emblem"><ShieldCheck size={16} /></div><div><strong>Personal vault</strong><span>{previewMode ? "Development preview · local only" : sync.state === "removed" ? "Removed from this vault" : sync.devices > 0 ? `Owner device · ${sync.devices + 1} devices` : "Owner device · local only"}</span></div></div>
        <button className="new-item" onClick={() => { if (!locked) setEditor({ mode: "create" }); }} disabled={locked}><Plus size={17} /> New item <span>⌘ N</span></button>
        <nav className="nav-list" aria-label="Vault filters">
          <p className="nav-caption">YOUR VAULT <span>{entries.length}</span></p>
          {filters.map((item) => <button key={item} className={`nav-item ${filter === item ? "active" : ""}`} onClick={() => setFilter(item)}><span className={`nav-icon ${item === "Favorites" ? "star" : ""}`}>{FILTER_ICONS[item]}</span>{item}<span className="nav-count">{entries.filter((entry) => inFilter(entry, item)).length}</span></button>)}
        </nav>
        <div className="sidebar-bottom"><button className="utility" onClick={() => setGeneratorOpen(true)}><Sparkles size={16} /> Generator</button><button className="utility" onClick={() => setArchivesOpen(true)} disabled={previewMode}><Archive size={16} /> Archive</button><button className="utility" onClick={() => setBackupOpen(true)} disabled={previewMode || locked}><HardDriveDownload size={16} /> Back up</button><button className="utility" onClick={() => setBrowserOpen(true)} disabled={previewMode}><Globe size={16} /> Browser</button><button className="utility" onClick={() => void openDeleted()} disabled={locked}><Trash2 size={16} /> Recently deleted</button><button className="utility" onClick={() => setSettingsOpen(true)}><SettingsIcon size={16} /> Settings</button><button className="device-card" onClick={() => setDevicesOpen(true)} disabled={devicesUnavailable}><div className="device-icon"><Fingerprint size={18} /></div><div><strong>This device</strong><span>{previewMode ? "Preview data only" : sync.state === "removed" ? "Removed · tap for details" : sync.devices > 0 ? `Syncs with ${sync.devices} other ${sync.devices === 1 ? "device" : "devices"}` : "Only device · tap to add one"}</span></div><span className={`online-dot ${sync.state === "synced" || sync.state === "idle" ? "" : "offline-dot"}`} /></button></div>
      </aside>

      <section className="content-pane">
        <header className="topbar"><div className="breadcrumbs"><span>Personal vault</span><ChevronRight size={15} /><strong>{filter}</strong></div><div className="top-actions"><button className={`sync-status ${syncLabel(sync).tone}`} onClick={() => setDevicesOpen(true)} disabled={devicesUnavailable} title={sync.message ?? undefined}><span className="status-dot" />{syncLabel(sync).text}</button><button className="icon-button" title="Lock vault" onClick={lock}><LockKeyhole size={18} /></button></div></header>
        <div className="workspace">
          <div className="list-column">
            <div className="list-heading"><div><p className="eyebrow">{filter.toUpperCase()}</p><h1>{visible.length} <span>items</span></h1></div><button className="icon-button bordered" title="Import" onClick={() => setImportOpen(true)} disabled={locked}><ArrowDownToLine size={17} /></button></div>
            {!locked && backupAge?.due && <div className="backup-reminder"><HardDriveDownload size={13} /><span>{backupAge.days === null ? "No backup of this vault yet" : `Last backup ${backupAge.days} days ago, from ${backupAge.device ? `device ${backupAge.device}` : "this computer"}`}</span><button onClick={() => setBackupOpen(true)} disabled={previewMode}>Back up</button></div>}
            {!locked && held.length > 0 && <div className="conflict-banner held-banner"><CircleAlert size={16} /><div><strong>{held.length} {held.length === 1 ? "change is" : "changes are"} held for review</strong><span>Written by a device that is not one of this vault's devices. Not part of your vault until you decide.</span></div><button className="conflict-action" onClick={() => setHeldOpen(true)}>Review</button></div>}
            <label className="search-box"><Search size={17} /><input ref={searchRef} aria-label="Search vault" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search your vault" /><kbd>⌘ K</kbd></label>
            <div className="entry-list">{visible.map((entry) => <button key={entry.id} className={`entry-row ${active?.id === entry.id ? "selected" : ""}`} onClick={() => setSelected(entry.id)}><div className={`entry-logo logo-${entry.kind}`}>{entry.kind === "secure_note" ? "▤" : entry.title.slice(0, 1)}</div><div className="entry-copy"><strong>{entry.title}</strong><span>{subtitle(entry)}</span></div><div className="entry-meta">{entry.favorite && <span className="favorite">★</span>}</div></button>)}{visible.length === 0 && <div className="empty-list"><Search size={22} /><strong>No matching items</strong><span>Try a different search or filter.</span></div>}</div>
          </div>
          <div className="detail-column">{locked && vaultStatus === "missing" && vaultProblem ? <UnreadablePanel problem={vaultProblem} onPutAway={() => void putUnreadableAway()} /> : locked && vaultStatus === "missing" && joining ? <JoinPanel onCancel={() => setJoining(false)} onJoined={() => void joined()} onNotice={setNotice} /> : locked && vaultStatus === "missing" && restoring ? <RestorePanel onCancel={() => setRestoring(false)} onRestored={(result) => void restored(result)} onNotice={setNotice} /> : locked && vaultStatus === "locked" && resetting ? <ResetPasswordPanel onCancel={() => setResetting(false)} onReset={() => void passwordReset()} onNotice={setNotice} /> : locked ? <div className="empty-detail">{fill && <div className="conflict-banner fill-banner"><CircleAlert size={16} /><div><strong>{fill.passkey ? `${fill.origin} asks for a passkey in ${fill.browser}` : `${fill.browser} asks to fill a ${fill.card ? "card" : "login"} into ${fill.origin}`}</strong><span>{vaultStatus === "missing" ? "This device has no vault to fill from." : `Unlock to choose ${fill.passkey ? "how to answer" : `a ${fill.card ? "card" : "login"}`}. Nothing is sent until you choose.`}</span></div><button className="conflict-action" onClick={() => void denyFill()}>Deny</button></div>}{vaultStatus === "missing" ? devices.resetArchive ? devices.resetReason === "left" ? <><CircleAlert size={25} /><h2>This device's copy was put away</h2><span>You had it moved to {devices.resetArchive}. Nothing was deleted. Join the new vault with an invitation from the device that started it, or create a new vault here.</span></> : <><CircleAlert size={25} /><h2>This device was removed from its vault</h2><span>Your other devices removed it, so its copy was moved to {devices.resetArchive}. Nothing was deleted. Join again with an invitation from one of your other devices, or create a new vault here.</span></> : <><Sparkles size={25} /><h2>Create your encrypted vault</h2><span>This device keeps its own vault. Choose a strong local password.</span></> : <><LockKeyhole size={25} /><h2>Vault locked</h2><span>{sync.pending > 0 ? `${sync.pending} received ${sync.pending === 1 ? "change is" : "changes are"} waiting to be verified when you unlock.` : "Unlock in the desktop window to view encrypted records."}</span></>}<div className="unlock-form"><input aria-label="Vault password" type="password" placeholder={vaultStatus === "missing" ? "New device password" : "Vault password"} value={unlockPassword} onChange={(event) => setUnlockPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void (vaultStatus === "missing" ? createVault() : unlock()); }} /><button onClick={() => void (vaultStatus === "missing" ? createVault() : unlock())}>{vaultStatus === "missing" ? <><Plus size={15} /> Create</> : <><UnlockKeyhole size={15} /> Unlock</>}</button></div>{vaultStatus === "missing" && !previewMode && <button className="link-button" onClick={() => setJoining(true)}>Join a vault from another device instead</button>}{vaultStatus === "missing" && !previewMode && <button className="link-button" onClick={() => setRestoring(true)}>Restore from a backup instead</button>}{vaultStatus === "locked" && !previewMode && <button className="link-button" onClick={() => setResetting(true)}>Forgot the password? Use the recovery key</button>}{vaultStatus === "missing" && devices.resetArchive && <button className="link-button" onClick={() => setArchivesOpen(true)}>Look into the copy that was put away</button>}</div> : active ? <><div className="detail-head"><div className={`detail-logo logo-${active.kind}`}>{active.kind === "secure_note" ? "▤" : active.title.slice(0, 1)}</div><div className="detail-title"><div><h2>{active.title}</h2>{active.url && <span>{active.url}</span>}</div></div></div><div className="detail-actions"><button onClick={() => void openEditor()}><span className="action-icon">✎</span> Edit</button>{shown?.hasPassword && <button onClick={() => void copySecret("password")}><Copy size={15} /> Copy password</button>}{shown?.hasTotp && <button onClick={() => void copySecret("code")}><Copy size={15} /> Copy one-time code</button>}</div><ItemRecord entry={active} detail={shown?.id === active.id ? shown : null} onCopyUsername={() => { void navigator.clipboard?.writeText(active.username ?? ""); setNotice("Username copied"); }} onCopy={(what, name) => void copySecret(what, name)} onRemovePasskey={(credentialId) => void removePasskey(credentialId)} /><button className="history-note" onClick={() => void openHistory()}><Clock3 size={15} /><div><strong>History</strong><span>Every version of this item, which device made it, and what it changed</span></div><ChevronRight size={15} /></button>{active.conflict && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Needs your decision</strong><span>Two signed revisions changed this item concurrently. Autofill is paused.</span></div><button className="conflict-action" onClick={() => void openReview()}>Review versions</button></div>}</> : <div className="empty-detail"><Sparkles size={25} /><h2>Select an item</h2><span>Your encrypted record will appear here after selection.</span></div>}</div>
        </div>
        {rowsChanged && !locked ? <div className="recovery-overlay"><div className="recovery-card rows-changed-card"><strong>Something in this vault's file was taken out, changed, or set back</strong><span>Since this computer last wrote to it, something outside Open Secret Manager removed or changed records in the vault's file, or put an earlier copy of the file in its place: an item, an edit, or a device's keys may be missing. Your other devices send back what they have at the next sync. If this is your only device, restore a backup to get it back. If you did not put back an earlier copy yourself, check this computer for software you do not trust.</span><button onClick={() => { setRowsChanged(false); void bridge.confirmRowsChanged().catch(() => {}); }}>I understand</button></div></div> : recoveryKey && !locked && <div className="recovery-overlay"><div className="recovery-card"><strong>Recovery key · store this offline</strong><code>{recoveryKey}</code><span>It is shown after every unlock until you confirm here that you stored it.</span><button onClick={() => { setRecoveryKey(null); void bridge.confirmRecoveryKey().catch(() => {}); }}>I stored it</button></div></div>}
        <footer className="footer-bar"><div><Wifi size={14} /><span>{previewMode ? "Development preview" : "Local vault"}</span><span className="footer-separator">•</span><span>{previewMode ? "No native sync session" : syncDetail(sync)}</span></div><button onClick={() => devicesUnavailable ? setNotice("Sync is unavailable in the browser preview") : setDevicesOpen(true)}>Devices <ChevronRight size={14} /></button></footer>
      </section>
      {generatorOpen && <div className="modal-backdrop" onClick={() => setGeneratorOpen(false)}><div className="generator-modal" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">TOOLS</p><h2>Password generator</h2></div><button className="icon-button" aria-label="Close" onClick={() => setGeneratorOpen(false)}><X size={18} /></button></div>{generator && <Generator choice={generator} onChoice={(choice) => void changeGenerator(choice)} onCopy={(value) => void copyGenerated(value)} />}</div></div>}
      {editor && <div className="modal-backdrop" onClick={() => setEditor(null)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">{editor.mode === "edit" ? "EDIT ITEM" : "NEW ITEM"}</p><h2>{editor.mode === "edit" ? editor.detail.title : "Create an item"}</h2></div><button className="icon-button" aria-label="Close" onClick={() => setEditor(null)}><X size={18} /></button></div><EntryEditor detail={editor.mode === "edit" ? editor.detail : undefined} generator={generator} onGeneratorChoice={(choice) => void changeGenerator(choice)} onCancel={() => setEditor(null)} onSave={saveEntry} onDelete={editor.mode === "edit" ? deleteEntry : undefined} /></div></div>}
      {review && <div className="modal-backdrop" onClick={() => setReview(null)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">RESOLVE CONFLICT</p><h2>{review.title}</h2></div><button className="icon-button" aria-label="Close" onClick={() => setReview(null)}><X size={18} /></button></div><p className="review-hint">These versions were changed independently. Keep one; it replaces all of them.{review.versions.some((version) => version.differs.includes("passkeys")) && " The passkeys of every version are kept, whichever you keep; remove one afterwards if you mean to."}</p><div className="version-list">{review.versions.map((version) => <div key={version.revision} className="version-card"><div className="version-meta"><strong>{version.thisDevice ? "This device" : `Device ${version.device}`}</strong><code>{version.revision.slice(0, 10)}</code></div>{version.deleted ? <span className="version-deleted">Deleted this item</span> : <dl><dt>Title</dt><dd>{version.title}</dd><dt>Username</dt><dd>{version.username || "—"}</dd><dt>Website</dt><dd>{version.url || "—"}</dd>{version.differs.length > 0 && <><dt>Differs in</dt><dd>{version.differs.join(", ")}</dd></>}</dl>}<button className="generate-button" onClick={() => void keepVersion(version.revision)}>{version.deleted ? "Keep deletion" : "Keep this version"}</button></div>)}</div></div></div>}
      {heldOpen && !locked && held.length > 0 && <div className="modal-backdrop" onClick={() => setHeldOpen(false)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">HELD FOR REVIEW</p><h2>Changes from outside this vault</h2></div><button className="icon-button" aria-label="Close" onClick={() => setHeldOpen(false)}><X size={18} /></button></div><HeldPanel held={held} otherDevices={sync.devices > 0} onDecide={(change, keep) => void decideHeld(change, keep)} /></div></div>}
      {backupOpen && !locked && <div className="modal-backdrop" onClick={() => setBackupOpen(false)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">BACKUP</p><h2>Back up this vault</h2></div><button className="icon-button" aria-label="Close" onClick={() => setBackupOpen(false)}><X size={18} /></button></div><BackupPanel recoveryOn={recoveryOn} onOpenDevices={() => { setBackupOpen(false); setDevicesOpen(true); }} onSaved={loadBackupAge} onNotice={setNotice} /></div></div>}
      {archivesOpen && <div className="modal-backdrop" onClick={() => { setArchivesOpen(false); void bridge.closeArchive().catch(() => {}); }}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">ARCHIVE</p><h2>Copies put away on this device</h2></div><button className="icon-button" aria-label="Close" onClick={() => { setArchivesOpen(false); void bridge.closeArchive().catch(() => {}); }}><X size={18} /></button></div><ArchivesPanel canCopy={!locked} onCopied={() => { void bridge.listEntries().then(setEntries).catch(() => {}); }} onNotice={setNotice} /></div></div>}
      {devicesOpen && <div className="modal-backdrop" onClick={() => setDevicesOpen(false)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">DEVICES</p><h2>Devices and sync</h2></div><button className="icon-button" aria-label="Close" onClick={() => setDevicesOpen(false)}><X size={18} /></button></div>{!locked && !recoveryOn && devices.setup === "ready" && <RecoveryPrompt onEnable={(key) => void enableRecovery(key)} />}<DevicesPanel sync={sync} devices={devices} invite={invite} locked={locked} onInvite={(votes) => void startInvite(votes)} onAnswer={(accept) => void answerInvite(accept)} onCancelInvite={() => void cancelInvite()} onSync={() => void syncNow()} onFound={() => void foundControlPlane()} onRemove={(device) => void removeDevice(device)} onCancelEnrollment={() => void cancelEnrollment()} onRejoined={() => void rejoined()} onRecovered={(key, summary) => void recovered(key, summary)} onUnlock={() => { setDevicesOpen(false); setNotice("Enter the vault password to unlock"); }} rejoining={rejoining} onRejoining={setRejoining} onReset={() => void resetDevice()} onNotice={setNotice} onCopy={(text) => { navigator.clipboard?.writeText(text); setNotice("Invitation copied · it works once"); }}  onRelayChanged={() => { void bridge.devices().then(setDevices).catch(() => {}); }} /></div></div>}
      {browserOpen && <div className="modal-backdrop" onClick={() => setBrowserOpen(false)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">BROWSER</p><h2>Filling into a browser</h2></div><button className="icon-button" aria-label="Close" onClick={() => setBrowserOpen(false)}><X size={18} /></button></div><BrowserPanel onNotice={setNotice} /></div></div>}
      {history && !locked && <div className="modal-backdrop" onClick={() => setHistory(null)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">HISTORY</p><h2>{history.title}</h2></div><button className="icon-button" aria-label="Close" onClick={() => setHistory(null)}><X size={18} /></button></div><HistoryPanel versions={history.versions} onRestore={(revision) => void restore(history.id, revision, history.versions.filter((version) => version.current).map((version) => version.revision), "Version restored")} /></div></div>}
      {deleted && !locked && <div className="modal-backdrop" onClick={() => setDeleted(null)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">DELETED</p><h2>Recently deleted</h2></div><button className="icon-button" aria-label="Close" onClick={() => setDeleted(null)}><X size={18} /></button></div><DeletedPanel items={deleted} onRestore={(item) => void restore(item.id, item.last, item.heads, `${item.title} restored`)} /></div></div>}
      {settingsOpen && <div className="modal-backdrop" onClick={() => setSettingsOpen(false)}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">SETTINGS</p><h2>On this computer</h2></div><button className="icon-button" aria-label="Close" onClick={() => setSettingsOpen(false)}><X size={18} /></button></div><SettingsPanel minutes={autoLockMinutes} locked={locked} onChange={(minutes) => void changeAutoLock(minutes)} onNotice={setNotice} /></div></div>}
      {importOpen && !locked && <div className="modal-backdrop" onClick={closeImport}><div className="generator-modal entry-editor" onClick={(event) => event.stopPropagation()}><div className="modal-head"><div><p className="eyebrow">IMPORT</p><h2>Bring in logins from another app</h2></div><button className="icon-button" aria-label="Close" onClick={closeImport}><X size={18} /></button></div><ImportPanel onImported={(added) => void imported(added)} onNotice={setNotice} /></div></div>}
      {fill && !locked && <div className="modal-backdrop"><div className="generator-modal entry-editor" role="dialog" aria-label={fill.passkey ? "A passkey" : fill.card ? "Fill a card" : "Fill a login"}><div className="modal-head"><div><p className="eyebrow">ASKED BY {fill.browser.toUpperCase()}</p><h2 className="fill-origin">{fill.passkey ? fill.passkey.ceremony === "create" ? `Save a passkey for ${fill.passkey.rpId}` : `Sign in to ${fill.passkey.rpId} with a passkey` : `Fill a ${fill.card ? "card" : "login"} into ${fill.origin}`}</h2></div></div>{fill.passkey ? <PasskeyPanel key={`${fill.requestId} ${fill.session}`} asked={fill} passkey={fill.passkey} onSend={sendPasskey} onUseBrowser={() => void useBrowserPasskey()} onDeny={() => void denyFill()} /> : fill.card ? <CardFillPanel key={`${fill.requestId} ${fill.session}`} asked={fill} onFill={(card) => void sendCard(card)} onDeny={() => void denyFill()} /> : <FillPanel key={`${fill.requestId} ${fill.session}`} asked={fill} onFill={(login) => void sendFill(login)} onDeny={() => void denyFill()} />}</div></div>}
      {notice && <div className={recoveryKey && !locked ? "toast toast-raised" : "toast"}><ShieldCheck size={15} />{notice}</div>}
    </main>
  );
}

function syncDetail(status: SyncStatus): string {
  if (status.state === "removed") return "This device was removed from the vault";
  if (status.replaced.length > 0 && status.state !== "syncing") return `Device ${shortDevice(status.replaced[0])} answers as a different device`;
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
  onInvite: (votes: boolean) => void;
  onAnswer: (accept: boolean) => void;
  onCancelInvite: () => void;
  onSync: () => void;
  onFound: () => void;
  onRemove: (device: string) => void;
  onCancelEnrollment: () => void;
  onRejoined: () => void;
  onRecovered: (recoveryKey: string, summary: string) => void;
  /** Takes the owner to the unlock form, which this dialog covers. */
  onUnlock: () => void;
  /** Whether this device is joining with the vault it already has. */
  rejoining: boolean;
  onRejoining: (active: boolean) => void;
  /** Puts a removed device's copy away so that it can join again. */
  onReset: () => void;
  onNotice: (text: string) => void;
  onCopy: (text: string) => void;
  /** The relay was set or taken away here. */
  onRelayChanged: () => void;
};

/** The relay the vault's devices reach each other through when they are on
 * different networks, which the owner runs and sets up here once. */
function RelaySection({ relay, locked, onChanged, onNotice }: { relay: DevicesInfo["relay"]; locked: boolean; onChanged: () => void; onNotice: (text: string) => void }) {
  const [editing, setEditing] = useState(false);
  const [code, setCode] = useState("");
  const [stopping, setStopping] = useState(false);
  async function save(value: string | null) {
    try {
      await bridge.setRelay(value);
      setEditing(false); setCode(""); setStopping(false);
      onNotice(value === null ? "Relay no longer used · your other devices stop using it once they sync" : "Relay set · your other devices use it once they sync");
      onChanged();
    } catch (error) {
      onNotice(commandMessage(error, "The relay could not be set"));
    }
  }
  if (editing) {
    return <div>
      <p className="review-hint">A relay passes your devices' encrypted connections along when they are on different networks, such as a phone on mobile data and this computer at home. It cannot read them or pass for a device. Run <code>osm-relay</code> on a machine they can all reach, and paste the code it prints.</p>
      <textarea className="join-code" aria-label="Relay code" rows={3} value={code} onChange={(event) => setCode(event.target.value)} placeholder="OSM-RELAY1-…" />
      <div className="form-actions"><button className="secondary" onClick={() => { setEditing(false); setCode(""); }}>Cancel</button><button className="generate-button" disabled={!code.trim()} onClick={() => void save(code)}>Use this relay</button></div>
    </div>;
  }
  if (!relay) {
    return <button className="link-button" disabled={locked} onClick={() => setEditing(true)}>On different networks? Reach your devices through a relay you run…</button>;
  }
  return <div className="peer-row relay-row">
    <div className="device-icon"><Globe size={18} /></div>
    <div><strong>Relay</strong><span>{relay.address} · {relay.connected ? "connected" : "not connected"}</span></div>
    {stopping
      ? <div className="form-actions"><button className="secondary" onClick={() => setStopping(false)}>Keep it</button><button className="generate-button" onClick={() => void save(null)}>Stop using it</button></div>
      : <div className="form-actions"><button className="secondary" disabled={locked} onClick={() => setEditing(true)}>Change…</button><button className="secondary" disabled={locked} onClick={() => setStopping(true)}>Stop using it…</button></div>}
  </div>;
}

/** A phone's invitation as a QR code, dark on light with its border, as scanners expect whatever the window's colours. */
function InvitationQr({ qr }: { qr: InviteQr }) {
  return <svg className="invite-qr" viewBox={`0 0 ${qr.side} ${qr.side}`} shapeRendering="crispEdges" role="img" aria-label="QR code of the invitation"><rect width={qr.side} height={qr.side} fill="#fff" /><path d={qr.path} fill="#000" /></svg>;
}

function DevicesPanel({ sync, devices, invite, locked, onInvite, onAnswer, onCancelInvite, onSync, onFound, onRemove, onCancelEnrollment, onRejoined, onRecovered, onUnlock, rejoining, onRejoining: setRejoining, onReset, onNotice, onCopy, onRelayChanged }: DevicesPanelProps) {
  const [removing, setRemoving] = useState<string | null>(null);
  const [choosing, setChoosing] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [leaving, setLeaving] = useState(false);

  if (recovering) return <RecoverPanel onCancel={() => setRecovering(false)} onRecovered={onRecovered} onNotice={onNotice} />;
  if (leaving && devices.setup === "ready") return <LeavePanel onCancel={() => setLeaving(false)} onNotice={onNotice} />;
  if (devices.setup === "removed") {
    return <div className="device-panel">
      <div className="conflict-banner"><CircleAlert size={16} /><div><strong>This device was removed from the vault</strong><span>Your other devices moved to a new key that this device never received. It gets no further changes, and nothing it writes is accepted by them. What it already held stays readable here.</span></div></div>
      <p className="review-hint">A removed device is normally reset on its own. That did not finish here. Resetting moves this device's copy to an archive folder on this computer; it is not deleted. Afterwards, join again with an invitation from one of your other devices.</p>
      {resetting
        ? <div className="form-actions"><button className="secondary" onClick={() => setResetting(false)}>Keep it as it is</button><button className="generate-button" onClick={() => { setResetting(false); onReset(); }}>Reset this device</button></div>
        : <button className="generate-button" onClick={() => setResetting(true)}>Reset this device to join again…</button>}
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
      <p className="review-hint">For {invite.votes ? "a computer that is usually on: it will vote" : "a phone, or a computer often off: it will not vote"}. {invite.votes ? "On the other device, choose “Join a vault from another device” and paste this invitation." : "On a phone, choose Scan the QR code and point it here; on a computer, choose “Join a vault from another device” and paste this invitation."} It works once and expires in 15 minutes.</p>
      {!invite.votes && <InvitationQr qr={invite.qr} />}
      <div className="generated-value"><code>{invite.code}</code><button onClick={() => onCopy(invite.code)} title="Copy invitation"><Copy size={16} /></button></div>
      <p className="review-hint">Waiting for the other device… The vault stays unlocked here meanwhile for the time without activity set in Settings; locking it ends the pairing.</p>
      <div className="form-actions"><button className="secondary" onClick={onCancelInvite}>Cancel</button></div>
    </div>;
  }
  if (devices.setup === "paired-before") {
    if (rejoining) return <JoinPanel keepsVault onCancel={() => setRejoining(false)} onJoined={() => { setRejoining(false); onRejoined(); }} onNotice={onNotice} />;
    return <div className="device-panel">
      <p className="review-hint">This device was paired by an earlier version. Your devices now agree together on which devices belong to the vault, so that a lost one can be removed. Set that up on one of the two devices only, then invite the other from it. Both keep their vaults.</p>
      {locked
        ? <button className="generate-button" onClick={onUnlock}>Unlock to continue</button>
        : <><button className="generate-button" onClick={onFound}>Set it up on this device</button>
          <button className="secondary" onClick={() => setRejoining(true)}>I set it up on the other device · join with an invitation</button></>}
    </div>;
  }
  if (devices.setup === "joining") {
    return <div className="device-panel"><p className="review-hint">This device is joining a vault. It becomes a member once the vault's devices have enrolled it.</p></div>;
  }
  if (devices.setup !== "ready") {
    return <div className="device-panel"><p className="review-hint">{locked ? "Unlock the vault to set up its devices." : "Devices are being set up…"}</p>{locked && <button className="generate-button" onClick={onUnlock}>Unlock</button>}</div>;
  }

  if (choosing && !invite) {
    return <div className="device-panel">
      <p className="review-hint">What kind of device are you adding? The devices that vote decide together which devices belong to the vault: adding or removing one needs most of them online. A device that does not vote holds the keys and syncs like the others, and being off never holds anything up.</p>
      <button className="generate-button" onClick={() => { setChoosing(false); onInvite(true); }}>A computer that is usually on · it votes</button>
      <button className="secondary" onClick={() => { setChoosing(false); onInvite(false); }}>A phone, or a computer often off · it does not vote</button>
      <div className="form-actions"><button className="secondary" onClick={() => setChoosing(false)}>Cancel</button></div>
    </div>;
  }

  const others = devices.members.filter((member) => !member.thisDevice);
  // This device first, then the others in the shell's order.
  const members = [...devices.members.filter((member) => member.thisDevice), ...others];
  const pending = devices.pending;
  const replaced = sync.replaced.filter((id) => others.some((member) => member.id === id));
  // The vault's only device that votes cannot be removed: no change could
  // complete without it.
  const onlyVoter = devices.members.filter((member) => member.votes).length === 1;
  return <div className="device-panel">
    {devices.networkKey === "in_file" && <p className="review-hint">No keystore on this computer sealed this device's network key, so it is kept in a file only your account can read. It is sealed the next time the app starts with a keystore that answers.</p>}
    {replaced.length > 0 && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Device {shortDevice(replaced[0])} answers as a different device</strong><span>Something else now answers at its address, so this device refuses it and cannot sync with it. If you started over as a new vault on that device, this copy was left behind: put it away to join the new vault. If you did not, change nothing here.</span></div><button className="conflict-action" onClick={() => setLeaving(true)}>Put this copy away…</button></div>}
    {members.map((member) => <div key={member.id} className="peer-row">
      <div className="device-icon"><Fingerprint size={18} /></div>
      <div><strong>{member.thisDevice ? "This device" : `Device ${shortDevice(member.id)}`}</strong><span>{member.thisDevice ? shortDevice(member.id) : sync.replaced.includes(member.id) ? `${member.address ?? "Its address"} · answers as a different device` : member.address ?? "Address not known yet"}{member.votes ? (onlyVoter && !member.thisDevice ? " · the only device that votes" : "") : " · does not vote"}</span>{addressLine(member) && <span className="peer-addresses">{addressLine(member)}</span>}</div>
      {!member.thisDevice && !pending && !(member.votes && onlyVoter) && (removing === member.id
        ? <div className="form-actions"><button className="secondary" onClick={() => setRemoving(null)}>Keep</button><button className="generate-button" onClick={() => { setRemoving(null); onRemove(member.id); }}>Remove</button></div>
        : <button className="secondary" disabled={locked} onClick={() => setRemoving(member.id)}>Remove…</button>)}
    </div>)}
    {removing && <p className="review-hint">Removing a device moves the others to a new key that it never receives. It keeps what it already had, so change any passwords it could have seen. This cannot be undone.</p>}
    {pending && pending.kind === "enroll" && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>{pending.cancelled ? "Cancelling an enrollment" : `Device ${shortDevice(pending.device)} is joining`}</strong><span>{pending.cancelled ? "Your devices are undoing it." : `It becomes a member${pending.votes ? "" : " without a vote"} once it has caught up. Until then no other device can be added or removed. If it never finishes, cancel it; it has received no key.`}</span></div>{!pending.cancelled && <button className="conflict-action" disabled={locked} onClick={onCancelEnrollment}>Cancel enrollment</button>}</div>}
    {pending && pending.kind === "remove" && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Removing device {shortDevice(pending.device)}</strong><span>Waiting for the remaining devices. The new key takes effect only when they have all agreed; bring them online to finish.</span></div></div>}
    <RelaySection relay={devices.relay} locked={locked} onChanged={onRelayChanged} onNotice={onNotice} />
    <p className="review-hint">{syncDetail(sync)}{sync.pending > 0 ? ` · ${sync.pending} waiting for unlock` : ""}</p>
    <p className="review-hint">{quorumHint(devices)}</p>
    {locked && <p className="review-hint">The vault is locked. This device still syncs and takes part in decisions, but adding or removing a device needs it unlocked.</p>}
    <div className="form-actions">
      {others.length > 0 && <button className="secondary" onClick={onSync} disabled={sync.state === "syncing"}>Sync now</button>}
      {locked
        ? <button className="generate-button" onClick={onUnlock}>Unlock to invite a device</button>
        : <button className="generate-button" onClick={() => setChoosing(true)} disabled={Boolean(pending)}>Invite a device</button>}
    </div>
    {others.length > 0 && <button className="link-button" onClick={() => setRecovering(true)}>Lost devices and cannot remove them? Start over as a new vault…</button>}
    {others.length > 0 && <button className="link-button" onClick={() => setLeaving(true)}>Another device started over? Put this copy away to join it…</button>}
  </div>;
}

/** The addresses of a device after the one shown first: for this device,
 * where it tells the others it can be reached, which they learn as they
 * connect; for another, where else it is tried. */
function addressLine(member: MemberInfo): string | null {
  if (member.thisDevice) return member.addresses.length > 0 ? `Tells your other devices it is at ${member.addresses.join(", ")}` : null;
  const rest = member.addresses.filter((address) => address !== member.address);
  return rest.length > 0 ? `Also at ${rest.join(", ")}` : null;
}

/** A request from a browser extension, for the owner to decide: which
 * login, if any, goes to the page that asked. Only logins stored for
 * exactly the page's origin can be chosen, and no password is shown. */
function FillPanel({ asked, onFill, onDeny }: { asked: FillAsked; onFill: (login: FillLogin) => void; onDeny: () => void }) {
  const [chosen, setChosen] = useState<string | null>(asked.logins.length === 1 ? asked.logins[0].id : null);
  const [left, setLeft] = useState(asked.secondsLeft);
  const [sending, setSending] = useState(false);
  useEffect(() => {
    const started = Date.now();
    const timer = window.setInterval(() => setLeft(Math.max(0, asked.secondsLeft - Math.floor((Date.now() - started) / 1000))), 1000);
    return () => window.clearInterval(timer);
  }, [asked.secondsLeft]);
  const login = asked.logins.find((candidate) => candidate.id === chosen);

  return <div className="device-panel">
    <p className="review-hint">You asked for this in the browser. Choose a login, and its user name and password go to that page. The form is not submitted for you.</p>
    {asked.logins.map((candidate) => <button key={candidate.id} className={`peer-row fill-choice ${chosen === candidate.id ? "selected" : ""}`} aria-pressed={chosen === candidate.id} onClick={() => setChosen(candidate.id)}>
      <div className="entry-logo logo-login">{candidate.title.slice(0, 1)}</div>
      <div><strong>{candidate.title}</strong><span>{[candidate.username || "No user name", candidate.conflict ? "has conflicting versions · the one your vault shows is sent" : ""].filter(Boolean).join(" · ")}</span></div>
    </button>)}
    {asked.logins.length === 0 && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>No login is stored for this page</strong><span>A login is offered only if its address is on exactly {asked.origin}: the same name, over https, on the same port.</span></div></div>}
    {asked.notOffered.map((other) => <p key={`${other.title} ${other.url}`} className="review-hint">“{other.title}” has the address {other.url}. {other.reason === "no_scheme" ? "Put https:// in front of that address for it to be offered here." : "That is an http address, and a login is only sent to an https page."}</p>)}
    <p className="review-hint">{left > 0 ? `The browser waits ${left} more ${left === 1 ? "second" : "seconds"}.` : "The browser has stopped waiting."}</p>
    <div className="form-actions"><button className="secondary" disabled={sending} onClick={onDeny}>Deny</button><button className="generate-button" disabled={!login || sending} onClick={() => { if (login) { setSending(true); onFill(login); } }}>{login ? `Fill ${login.title}` : asked.logins.length === 0 ? "Nothing to fill" : "Choose a login"}</button></div>
  </div>;
}

/** How a card form's fields are named to the owner. */
const CARD_FIELD_NAMES: Record<CardFieldName, string> = {
  number: "the number", cardholder: "the cardholder's name", expiry: "the expiry", expiry_month: "the expiry month", expiry_year: "the expiry year", security_code: "the security code",
};

/** "a, b, and c", as a sentence names several things. */
function listed(names: string[]): string {
  return names.length <= 2 ? names.join(" and ") : `${names.slice(0, -1).join(", ")}, and ${names[names.length - 1]}`;
}

/** A request from a browser extension for a card: where each of its fields would go, and the card the owner chooses. A card belongs to no site, so every card is offered. */
function CardFillPanel({ asked, onFill, onDeny }: { asked: FillAsked; onFill: (card: FillCardChoice) => void; onDeny: () => void }) {
  const cards = asked.card?.cards ?? [];
  const [chosen, setChosen] = useState<string | null>(cards.length === 1 ? cards[0].id : null);
  const [left, setLeft] = useState(asked.secondsLeft);
  const [sending, setSending] = useState(false);
  useEffect(() => {
    const started = Date.now();
    const timer = window.setInterval(() => setLeft(Math.max(0, asked.secondsLeft - Math.floor((Date.now() - started) / 1000))), 1000);
    return () => window.clearInterval(timer);
  }, [asked.secondsLeft]);
  const card = cards.find((candidate) => candidate.id === chosen);

  return <div className="device-panel">
    <p className="review-hint">You asked for this in the browser. A card belongs to no site, so any page can ask for one: choose a card only if this is where you mean to pay. The form is not submitted for you.</p>
    {(asked.card?.documents ?? []).map((document) => <p key={`${document.origin} ${document.page}`} className="review-hint card-document">{listed(document.fields.map((field) => CARD_FIELD_NAMES[field])).replace(/^./, (first) => first.toUpperCase())} {document.fields.length === 1 ? "goes" : "go"} to <strong>{document.origin}</strong>{document.page ? ", the page itself." : ", a frame in the page."}</p>)}
    {cards.map((candidate) => <button key={candidate.id} className={`peer-row fill-choice ${chosen === candidate.id ? "selected" : ""}`} aria-pressed={chosen === candidate.id} onClick={() => setChosen(candidate.id)}>
      <div className="entry-logo logo-card">{candidate.title.slice(0, 1)}</div>
      <div><strong>{candidate.title}</strong><span>{[candidate.brand || "Card", candidate.ending ? `•••• ${candidate.ending}` : ""].filter(Boolean).join(" ")}</span></div>
    </button>)}
    {cards.length === 0 && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>No card is stored</strong><span>Add a card in this app first. A card two devices changed at once is filled only once you settle which version to keep.</span></div></div>}
    <p className="review-hint">{left > 0 ? `The browser waits ${left} more ${left === 1 ? "second" : "seconds"}.` : "The browser has stopped waiting."}</p>
    <div className="form-actions"><button className="secondary" disabled={sending} onClick={onDeny}>Deny</button><button className="generate-button" disabled={!card || sending} onClick={() => { if (card) { setSending(true); onFill(card); } }}>{card ? `Fill ${card.title}` : cards.length === 0 ? "Nothing to fill" : "Choose a card"}</button></div>
  </div>;
}

/**
 * A page's request for a passkey: for a new one, where it goes; to sign in,
 * which passkey. When the site asks to verify the owner, the owner is
 * verified here each time: by the system's check (Touch ID or the Mac's
 * password) or this device's password. The browser's own passkeys can
 * answer instead.
 */
function PasskeyPanel({ asked, passkey, onSend, onUseBrowser, onDeny }: { asked: FillAsked; passkey: PasskeyAsked; onSend: (choice: PasskeyChoice) => Promise<void>; onUseBrowser: () => void; onDeny: () => void }) {
  const creating = passkey.ceremony === "create";
  const [into, setInto] = useState<string | null>(null);
  const [chosen, setChosen] = useState<string | null>(passkey.passkeys.length === 1 ? passkey.passkeys[0].credentialId : null);
  const [password, setPassword] = useState("");
  const [left, setLeft] = useState(asked.secondsLeft);
  const [sending, setSending] = useState(false);
  useEffect(() => {
    const started = Date.now();
    const timer = window.setInterval(() => setLeft(Math.max(0, asked.secondsLeft - Math.floor((Date.now() - started) / 1000))), 1000);
    return () => window.clearInterval(timer);
  }, [asked.secondsLeft]);
  const verifying = passkey.verification !== "discouraged";
  const signIn = passkey.passkeys.find((candidate) => candidate.credentialId === chosen);
  const account = (name: string, shown: string) => shown && shown !== name ? `${name} (${shown})` : name || "No account name";
  const ready = (creating || signIn) && (!verifying || password.length > 0 || passkey.ownerCheck);
  const send = () => {
    if (!ready) return;
    setSending(true);
    // A refused choice leaves the panel for the owner to choose again.
    void onSend({
      into: creating ? into : undefined,
      itemId: signIn?.itemId,
      credentialId: signIn?.credentialId,
      password: verifying && password ? password : undefined,
      ownerCheck: verifying && !password && passkey.ownerCheck,
    }).finally(() => setSending(false));
  };

  return <div className="device-panel">
    <p className="review-hint">{creating
      ? <>The page <strong>{asked.origin}</strong> asks to make a passkey for <strong>{passkey.rpId}</strong>, for the account {account(passkey.userName, passkey.userDisplayName)}. It goes into your vault, on all your devices; the page gets only what lets the site check a sign-in.</>
      : <>The page <strong>{asked.origin}</strong> asks you to sign in to <strong>{passkey.rpId}</strong> with a passkey. Choose one, and only the site's sign-in, signed with it, goes to the page.</>}</p>
    {creating ? <>
      <button className={`peer-row fill-choice ${into === null ? "selected" : ""}`} aria-pressed={into === null} onClick={() => setInto(null)}>
        <div className="entry-logo logo-login">+</div>
        <div><strong>A new login for {passkey.rpId}</strong><span>{passkey.userName || "No account name"}</span></div>
      </button>
      {passkey.logins.map((login) => <button key={login.id} className={`peer-row fill-choice ${into === login.id ? "selected" : ""}`} aria-pressed={into === login.id} onClick={() => setInto(login.id)}>
        <div className="entry-logo logo-login">{login.title.slice(0, 1)}</div>
        <div><strong>Add to {login.title}</strong><span>{login.username || "No user name"}</span></div>
      </button>)}
    </> : <>
      {passkey.passkeys.map((candidate) => <button key={`${candidate.itemId} ${candidate.credentialId}`} className={`peer-row fill-choice ${chosen === candidate.credentialId ? "selected" : ""}`} aria-pressed={chosen === candidate.credentialId} onClick={() => setChosen(candidate.credentialId)}>
        <div className="entry-logo logo-login">{candidate.title.slice(0, 1)}</div>
        <div><strong>{account(candidate.userName, candidate.userDisplayName)}</strong><span>On {candidate.title}</span></div>
      </button>)}
      {passkey.passkeys.length === 0 && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>No passkey for {passkey.rpId} is in your vault</strong><span>Use the browser's own passkeys, or deny.</span></div></div>}
    </>}
    {verifying && <div className="passkey-verify">
      <p className="review-hint">The site asks to verify it is you. {passkey.ownerCheck ? "This Mac checks it with Touch ID or its password when you go on, or type this device's password here instead." : "Type this device's password."}</p>
      <input aria-label="This device's password" type="password" placeholder="This device's password" value={password} autoComplete="off" onChange={(event) => setPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") send(); }} />
    </div>}
    <p className="review-hint">{left > 0 ? `The browser waits ${left} more ${left === 1 ? "second" : "seconds"}.` : "The browser has stopped waiting."}</p>
    <div className="form-actions">
      <button className="secondary" disabled={sending} onClick={onDeny}>Deny</button>
      <button className="secondary" disabled={sending} onClick={onUseBrowser}>Use the browser's passkeys</button>
      <button className="generate-button" disabled={!ready || sending} onClick={send}>{creating ? "Save passkey" : signIn ? "Sign in" : "Choose a passkey"}</button>
    </div>
  </div>;
}

/** Which browsers can reach this app, and the switch for each. */
function BrowserPanel({ onNotice }: { onNotice: (text: string) => void }) {
  const [status, setStatus] = useState<BrowserStatus | null>(null);
  useEffect(() => { void bridge.browserStatus().then(setStatus).catch(() => {}); }, []);

  async function change(browser: BrowserInfo, connect: boolean) {
    try {
      setStatus(await (connect ? bridge.connectBrowser(browser.id) : bridge.disconnectBrowser(browser.id)));
      onNotice(connect ? `${browser.name} can now reach this app` : `${browser.name} can no longer reach this app`);
    } catch (error) {
      const code = (error as { code?: string } | null)?.code;
      onNotice(code === "host_missing" ? "The program that browsers start was not found beside this app"
        : code === "temporary_place" ? "This app is running from a place that is gone when it quits"
        : code === "no_browser" ? `${browser.name} was not found on this device`
        : commandMessage(error, `${browser.name} could not be ${connect ? "connected" : "disconnected"}`));
    }
  }

  if (!status) return <div className="device-panel"><p className="review-hint">Looking…</p></div>;
  if (!status.supported) return <div className="device-panel"><p className="review-hint">Filling into a browser is not available on this system.</p></div>;
  return <div className="device-panel">
    <p className="review-hint">A browser extension can ask this app to fill a login into the page you are on. Each time, this window comes forward and you choose the login here; only its user name and password go to that page. The extension never sees what your vault holds.</p>
    {!status.listening && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>This app is not listening for the browser</strong><span>{status.problem ?? "It could not start listening."}</span></div></div>}
    {status.browsers.length === 0 && <p className="review-hint">No browser this app can connect was found on this account.</p>}
    {status.browsers.map((browser) => <div key={browser.id} className="peer-row">
      <div className="device-icon"><Globe size={18} /></div>
      <div><strong>{browser.name}</strong><span>{browser.state === "connected" ? "Connected" : browser.state === "other" ? browser.pointsTo ? `Set up to start another program: ${browser.pointsTo}` : "Set up for something other than this app" : "Not connected"}</span></div>
      {browser.state === "connected"
        ? <button className="secondary" onClick={() => void change(browser, false)}>Disconnect</button>
        : <button className="secondary" disabled={!status.host || status.temporaryPlace} onClick={() => void change(browser, true)}>{browser.state === "other" ? "Repair" : "Connect"}</button>}
    </div>)}
    {!status.host && <p className="review-hint">The program that browsers start to reach this app was not found beside it, so no browser can be connected.</p>}
    {status.temporaryPlace && <p className="review-hint">This app is running from a place that is gone when it quits, so no browser can be pointed at it. Install the app first (on a Mac, move it into Applications and open it from there), then connect the browser.</p>}
    <p className="review-hint">Connecting writes one small file into the browser's own folder. It says where that program is and which one extension may start it. Disconnecting removes the file.</p>
    <p className="review-hint">Install the extension from the Chrome Web Store or Firefox's add-ons site, then connect that browser here. Connecting changes nothing you would notice until the extension is installed.</p>
  </div>;
}

/** How an archived item relates to the vault here now. */
function relationLabel(item: ArchivedItem): string {
  switch (item.relation) {
    case "same": return "Already in your vault";
    case "differs": return `Differs from your vault in ${item.changed.join(", ")}`;
    case "absent": return "Not in your vault";
    default: return "";
  }
}

/** Copies of a vault that were put away on this device: when it was removed,
 * when it left a vault that was replaced, or when it started over. One can
 * be opened with the password it had, an item copied into the vault here,
 * and the copy deleted. */
function ArchivesPanel({ canCopy, onCopied, onNotice }: { canCopy: boolean; onCopied: () => void; onNotice: (text: string) => void }) {
  const [archives, setArchives] = useState<ArchiveInfo[] | null>(null);
  const [unlocking, setUnlocking] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [working, setWorking] = useState(false);
  const [opened, setOpened] = useState<{ archive: ArchiveInfo; items: ArchivedItem[] } | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const load = () => { void bridge.listArchives().then(setArchives).catch(() => setArchives([])); };
  useEffect(load, []);
  const when = (archive: ArchiveInfo) => new Date(archive.archivedAt * 1000).toLocaleString();

  async function open(archive: ArchiveInfo) {
    setWorking(true);
    try {
      setOpened({ archive, items: await bridge.openArchive(archive.name, password) });
      setPassword("");
      setUnlocking(null);
    } catch (error) {
      onNotice((error as { code?: string } | null)?.code === "invalid_credentials" ? "That is not the password this copy had" : commandMessage(error, "That copy could not be opened"));
    }
    setWorking(false);
  }

  async function copy(item: ArchivedItem) {
    if (!opened) return;
    try {
      setOpened({ archive: opened.archive, items: await bridge.copyFromArchive(item.id) });
      onCopied();
      onNotice(item.relation === "differs" ? `Copied as “${item.title} (archived copy)”` : `${item.title} copied into your vault`);
    } catch (error) {
      onNotice(commandMessage(error, "That item could not be copied"));
    }
  }

  async function close() {
    await bridge.closeArchive().catch(() => {});
    setOpened(null);
  }

  async function remove(archive: ArchiveInfo) {
    try {
      await bridge.deleteArchive(archive.name);
      setDeleting(null);
      load();
      onNotice("That copy was deleted");
    } catch (error) {
      onNotice(commandMessage(error, "That copy could not be deleted"));
    }
  }

  if (opened) {
    return <div className="device-panel">
      <p className="review-hint">The copy put away on {when(opened.archive)}. {canCopy ? "Copying an item adds it to your vault as a new item; nothing here is changed." : "Unlock, join, or create a vault to copy items into it."} Passwords are not shown here.</p>
      {opened.items.length === 0 && <p className="review-hint">This copy holds no items.</p>}
      {opened.items.map((item) => <div key={item.id} className="peer-row">
        <div className={`entry-logo logo-${item.kind}`}>{item.kind === "secure_note" ? "▤" : item.title.slice(0, 1)}</div>
        <div><strong>{item.title}</strong><span>{[item.username || item.url, relationLabel(item), item.conflict ? "had conflicting versions" : ""].filter(Boolean).join(" · ") || "—"}</span></div>
        {canCopy && item.relation !== "same" && <button className="secondary" onClick={() => void copy(item)}>Copy into vault</button>}
      </div>)}
      <div className="form-actions"><button className="secondary" onClick={() => void close()}>Back</button></div>
    </div>;
  }
  if (archives === null) return <div className="device-panel"><p className="review-hint">Looking…</p></div>;
  return <div className="device-panel">
    <p className="review-hint">{archives.length === 0 ? "No copy of a vault has been put away on this device." : "A copy is put away when this device is removed from its vault, leaves a vault that was replaced, or starts over as a new vault. It may hold changes that never reached another device. Open one with the password it had."}</p>
    {archives.map((archive) => <div key={archive.name} className="peer-row archive-row">
      <div className="device-icon"><Archive size={18} /></div>
      <div><strong>Put away {when(archive)}</strong><span>{archive.path}</span></div>
      {deleting === archive.name
        ? <div className="form-actions"><button className="secondary" onClick={() => setDeleting(null)}>Keep</button><button className="generate-button" onClick={() => void remove(archive)}>Delete for good</button></div>
        : unlocking === archive.name
          ? null
          : <div className="form-actions">{archive.hasVault && <button className="secondary" onClick={() => { setUnlocking(archive.name); setPassword(""); setDeleting(null); }}>Open…</button>}<button className="secondary" onClick={() => { setDeleting(archive.name); setUnlocking(null); }}>Delete…</button></div>}
      {unlocking === archive.name && <div className="unlock-form archive-unlock"><input aria-label="Password of that copy" type="password" autoFocus placeholder="The password this copy had" value={password} disabled={working} onChange={(event) => setPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && password) void open(archive); }} /><button disabled={working || !password} onClick={() => void open(archive)}>{working ? "Opening…" : "Open"}</button><button className="archive-cancel" disabled={working} onClick={() => setUnlocking(null)}>Cancel</button></div>}
    </div>)}
    {deleting && <p className="review-hint">Deleting removes the folder and everything in it from this computer. If the copy holds anything that is not in your vault, open it and copy that first. This cannot be undone.</p>}
  </div>;
}

/** What a held change would do, in the owner's terms. */
function heldHeading(change: HeldChange): string {
  switch (change.change) {
    case "new": return `New item · ${change.title}`;
    case "delete": return change.title ? `Deletes ${change.title}` : "Deletes an item that is already gone here";
    case "restore": return `Brings back ${change.title}, which is deleted here`;
    default: return `Changes ${change.title}`;
  }
}

/** Changes written by a device outside the vault's devices, for the owner
 * to keep or reject. No secret is shown: a changed password is only named. */
function HeldPanel({ held, otherDevices, onDecide }: { held: HeldChange[]; otherDevices: boolean; onDecide: (change: HeldChange, keep: boolean) => void }) {
  return <>
    <p className="review-hint">These changes were written by a device that is not one of this vault's devices, usually one you removed. They are not part of your vault until you decide. Passwords are not shown here; a changed one is only named.</p>
    <div className="version-list">{held.map((change) => {
      const deletion = change.change === "delete";
      return <div key={change.revision} className="version-card">
        <div className="version-meta"><strong>{heldHeading(change)}</strong><code>{change.revision.slice(0, 10)}</code></div>
        <span className="held-author">{change.removedDevice ? `From device ${change.device}, which was removed from this vault.${otherDevices ? " Your decision reaches your other devices at the next sync." : ""}` : `From device ${change.device}, which this device does not know. If you have just added a device, sync first: its changes are accepted on their own once this device knows it.`}</span>
        {!deletion && <dl><dt>Title</dt><dd>{change.title}</dd><dt>Username</dt><dd>{change.username || "—"}</dd><dt>Website</dt><dd>{change.url || "—"}</dd>{change.change === "edit" && <><dt>Differs in</dt><dd>{change.changed.join(", ") || "nothing you would see"}</dd></>}</dl>}
        {deletion
          // Deleting on the word of a device outside the vault is not the emphasized answer.
          ? <div className="form-actions"><button className="secondary" onClick={() => onDecide(change, true)}>Delete the item</button><button className="generate-button" onClick={() => onDecide(change, false)}>Keep the item</button></div>
          : <div className="form-actions"><button className="secondary" onClick={() => onDecide(change, false)}>Reject</button><button className="generate-button" onClick={() => onDecide(change, true)}>Keep this change</button></div>}
      </div>;
    })}</div>
  </>;
}

/** Saves a backup, which the recovery key opens, and says what it holds as
 * read back from the file. */
function BackupPanel({ recoveryOn, onOpenDevices, onSaved, onNotice }: { recoveryOn: boolean; onOpenDevices: () => void; onSaved: () => void; onNotice: (text: string) => void }) {
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<SavedBackup | null>(null);

  async function save() {
    setSaving(true);
    try {
      const result = await bridge.saveBackup();
      if (result) { setSaved(result); onSaved(); }
    } catch (error) {
      const code = (error as { code?: string } | null)?.code;
      onNotice(code === "exists" ? "A file of that name is already there · an older backup is never replaced, so choose another name" : commandMessage(error, "The backup could not be saved"));
    } finally {
      setSaving(false);
    }
  }

  return <div className="device-panel">
    <p className="review-hint">A backup is one encrypted file with every item and its history. It opens with the vault's recovery key, not with a password. Keep the file and the key apart: the file wherever you like, the key offline.</p>
    <p className="review-hint">If every device of this vault is lost, a new computer restores the backup with the recovery key, as a new vault that your other devices join again. Changes made after the backup are not in it.</p>
    {!recoveryOn && <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Recovery is off on this device</strong><span>A backup needs it. Turn it on with the recovery key in Devices, or back up from another of your devices.</span></div><button className="conflict-action" onClick={onOpenDevices}>Open Devices</button></div>}
    {saved && <div className="conflict-banner saved-banner"><ShieldCheck size={16} /><div><strong>Saved and read back</strong><span>{saved.path}</span><span>{saved.items} {saved.items === 1 ? "item" : "items"} with {saved.revisions} {saved.revisions === 1 ? "version" : "versions"}{saved.held > 0 ? ` · ${saved.held} held for review` : ""}</span></div></div>}
    <div className="form-actions"><button className="generate-button" disabled={saving || !recoveryOn} onClick={() => void save()}>{saving ? "Saving…" : saved ? "Save another backup" : "Choose where to save"}</button></div>
  </div>;
}

/** On a device without a vault: makes a new vault from a backup, for when
 * no device of the vault is left to join from. */
function RestorePanel({ onCancel, onRestored, onNotice }: { onCancel: () => void; onRestored: (result: Restored) => void; onNotice: (text: string) => void }) {
  const [file, setFile] = useState<string | null>(null);
  const [recoveryKey, setRecoveryKey] = useState("");
  const [password, setPassword] = useState("");
  const [working, setWorking] = useState(false);

  async function choose() {
    try {
      const name = await bridge.chooseBackup();
      if (name) setFile(name);
    } catch (error) {
      onNotice(commandMessage(error, "The backup could not be chosen"));
    }
  }

  async function restore() {
    if (password.length < 12) { onNotice("Use at least 12 characters for this device password"); return; }
    setWorking(true);
    try {
      const result = await bridge.restoreBackup(recoveryKey, password);
      setRecoveryKey("");
      setPassword("");
      onRestored(result);
    } catch (error) {
      setWorking(false);
      const code = (error as { code?: string } | null)?.code;
      if (code === "invalid_credentials") onNotice("That recovery key does not open this backup · nothing was changed");
      else if (code === "invalid_recovery_key") onNotice("That is not a recovery key · check it for typos");
      else if (code === "vault_exists") onNotice("This device already has a vault · only a device without one restores");
      else onNotice(commandMessage(error, `The backup could not be restored · ${(error as { message?: string } | null)?.message ?? "unknown error"}`));
    }
  }

  return <div className="empty-detail">
    <HardDriveDownload size={25} /><h2>Restore from a backup</h2>
    <span>Use this only when no device of the vault is left. If one is, join from it instead. A restored vault is a new vault with a new recovery key, and your other devices join it again.</span>
    <div className="form-actions join-actions"><button className="secondary" disabled={working} onClick={() => void choose()}>{file ? `${file} · choose another` : "Choose the backup file"}</button></div>
    <div className="unlock-form"><input aria-label="Recovery key" type="password" placeholder="Recovery key, OSM-RK1-…" value={recoveryKey} disabled={working} onChange={(event) => setRecoveryKey(event.target.value)} /></div>
    <div className="unlock-form"><input aria-label="New device password" type="password" placeholder="New password for this device" value={password} disabled={working} onChange={(event) => setPassword(event.target.value)} /></div>
    <div className="form-actions join-actions"><button className="secondary" disabled={working} onClick={onCancel}>Cancel</button><button className="generate-button" disabled={working || !file || !recoveryKey.trim() || !password} onClick={() => void restore()}>{working ? "Restoring…" : "Restore"}</button></div>
  </div>;
}

/** A vault file is on this device that cannot be opened. Nothing can be
 * made over it, so the owner has it put away first. */
/** In place of the whole window when the app could not start on this
 * computer's files: what it found, and nothing to do here but read it. */
export function StartupProblem({ problem }: { problem: string }) {
  return <main className="app-shell">
    <div className="empty-detail startup-problem">
      <CircleAlert size={25} /><h2>Open Secret Manager cannot start on this computer's files</h2>
      <span>{problem}</span>
      <span>If a later version of this app wrote them, install that version again. Nothing was changed, and nothing runs until then.</span>
    </div>
  </main>;
}

function UnreadablePanel({ problem, onPutAway }: { problem: string; onPutAway: () => void }) {
  return <div className="empty-detail">
    <CircleAlert size={25} /><h2>This device's vault cannot be opened</h2>
    <span>{problem}</span>
    <span>If it was written by a newer version of this app, install that version instead. Otherwise put it away: it moves, untouched, to an archive folder on this computer, and nothing is deleted. Then join from another of your devices, restore a backup, or create a new vault.</span>
    <div className="form-actions join-actions"><button className="generate-button" onClick={onPutAway}>Put it away</button></div>
  </div>;
}

/** For a forgotten password: the recovery key unlocks this device and a new
 * password replaces the old one here. */
function ResetPasswordPanel({ onCancel, onReset, onNotice }: { onCancel: () => void; onReset: () => void; onNotice: (text: string) => void }) {
  const [recoveryKey, setRecoveryKey] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [working, setWorking] = useState(false);

  async function reset() {
    if (password.length < 12) { onNotice("Use at least 12 characters for this device password"); return; }
    if (password !== again) { onNotice("The two passwords differ"); return; }
    setWorking(true);
    try {
      await bridge.resetPassword(recoveryKey, password);
      setRecoveryKey("");
      setPassword("");
      setAgain("");
      onReset();
    } catch (error) {
      setWorking(false);
      const code = (error as { code?: string } | null)?.code;
      if (code === "invalid_credentials") onNotice("That recovery key does not open this vault · nothing was changed");
      else if (code === "invalid_recovery_key") onNotice("That is not a recovery key · check it for typos");
      else if (code === "recovery_not_enabled") onNotice("Recovery is off on this device · ask another of your devices to remove this one, then join again");
      else onNotice(commandMessage(error, "The password could not be replaced"));
    }
  }

  return <div className="empty-detail">
    <KeyRound size={25} /><h2>Set a new password</h2>
    <span>The recovery key unlocks this device, and the new password replaces the old one here. Your other devices keep their own passwords.</span>
    <div className="unlock-form"><input aria-label="Recovery key" type="password" placeholder="Recovery key, OSM-RK1-…" value={recoveryKey} disabled={working} onChange={(event) => setRecoveryKey(event.target.value)} /></div>
    <div className="unlock-form"><input aria-label="New device password" type="password" placeholder="New password for this device" value={password} disabled={working} onChange={(event) => setPassword(event.target.value)} /></div>
    <div className="unlock-form"><input aria-label="New device password again" type="password" placeholder="The new password again" value={again} disabled={working} onChange={(event) => setAgain(event.target.value)} /></div>
    <div className="form-actions join-actions"><button className="secondary" disabled={working} onClick={onCancel}>Cancel</button><button className="generate-button" disabled={working || !recoveryKey.trim() || !password || !again} onClick={() => void reset()}>{working ? "Unlocking…" : "Set the new password"}</button></div>
  </div>;
}

/** The last resort when too many devices are lost for the rest to remove
 * them: this device starts a new vault from what it holds. */
function RecoverPanel({ onCancel, onRecovered, onNotice }: { onCancel: () => void; onRecovered: (recoveryKey: string, summary: string) => void; onNotice: (text: string) => void }) {
  const [password, setPassword] = useState("");
  const [working, setWorking] = useState(false);

  async function recover() {
    setWorking(true);
    try {
      const result = await bridge.recoverVault(password);
      setPassword("");
      const carried = `${result.items} ${result.items === 1 ? "item" : "items"} carried over`;
      const conflicts = result.conflicts > 0 ? ` · ${result.conflicts} still need your decision` : "";
      const held = result.heldLeftBehind > 0 ? ` · ${result.heldLeftBehind} held for review stayed in the old vault` : "";
      onRecovered(result.recoveryKey, `New vault started · ${carried}${conflicts}${held}`);
    } catch (error) {
      setWorking(false);
      onNotice(commandMessage(error, "The new vault could not be started"));
    }
  }

  return <div className="device-panel">
    <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Start over as a new vault</strong><span>Use this only when you cannot reach enough of your devices to remove the lost ones. If they can be reached, remove the lost device instead.</span></div></div>
    <p className="review-hint">This device makes a new vault from what it holds now: the current version of every item, without earlier history. The new vault has new keys and a new recovery key, which you will be shown once.</p>
    <p className="review-hint">Your other devices are not part of the new vault and can no longer sync with this one. On each device you still have, join again with an invitation from here. A lost device keeps what it already had, so change any passwords it could have seen.</p>
    <p className="review-hint">The old vault is not deleted. It is moved, untouched, to an archive folder next to the new one.</p>
    <div className="unlock-form"><input aria-label="Vault password" type="password" placeholder="Vault password, to confirm" value={password} disabled={working} onChange={(event) => setPassword(event.target.value)} /></div>
    <div className="form-actions"><button className="secondary" disabled={working} onClick={onCancel}>Cancel</button><button className="generate-button" disabled={working || !password} onClick={() => void recover()}>{working ? "Starting the new vault…" : "Start over as a new vault"}</button></div>
  </div>;
}

/** For a device left behind when another one started over as a new vault:
 * nothing removed it, so the owner says so here. Its copy goes to an archive
 * folder and the device can then join the new vault. */
function LeavePanel({ onCancel, onNotice }: { onCancel: () => void; onNotice: (text: string) => void }) {
  const [password, setPassword] = useState("");
  const [working, setWorking] = useState(false);

  async function leave() {
    setWorking(true);
    try {
      // On success the shell reports the reset, which closes this dialog.
      await bridge.leaveVault(password);
      setPassword("");
    } catch (error) {
      setWorking(false);
      onNotice(commandMessage(error, "This device's copy could not be put away"));
    }
  }

  return <div className="device-panel">
    <div className="conflict-banner"><CircleAlert size={16} /><div><strong>Put this device's copy away</strong><span>Use this only if this vault was replaced: another of your devices started over as a new vault, and this one was left behind.</span></div></div>
    <p className="review-hint">This device's copy of the vault is moved, untouched, to an archive folder on this computer. Nothing is deleted. Afterwards this device has no vault, and joins the new one with an invitation from the device that started it. Anything changed here that never reached that device stays in the archived copy only.</p>
    <p className="review-hint">If your other devices still use this vault, do not do this; remove this device from one of them instead. Put away like this, it would still count as one of the vault's devices and never answer, which can leave the others unable to add or remove a device.</p>
    <div className="unlock-form"><input aria-label="Device password" type="password" placeholder="This device's password, to confirm" value={password} disabled={working} onChange={(event) => setPassword(event.target.value)} /></div>
    <div className="form-actions"><button className="secondary" disabled={working} onClick={onCancel}>Cancel</button><button className="generate-button" disabled={working || !password} onClick={() => void leave()}>{working ? "Putting it away…" : "Put this copy away"}</button></div>
  </div>;
}

/** Says how many devices a change needs, in terms the owner can act on. */
function quorumHint(devices: DevicesInfo): string {
  const count = devices.members.length;
  if (count <= 1) return "Each device keeps a full encrypted copy and they sync directly, with no server. You will compare a six-digit code on both screens.";
  const voting = devices.members.filter((member) => member.votes).length;
  const others = voting < count ? " Devices that do not vote never count toward this." : "";
  if (voting === 1) return `Adding or removing a device needs only the device that votes to be online. It cannot itself be removed while it is the only one: invite a computer that votes first.${others}`;
  if (voting === 2) return `Adding or removing a device needs both devices that vote online. With three that vote, one can be away or lost and still be removed.${others}`;
  return `Adding or removing a device needs ${devices.quorum} of the ${voting} devices that vote online. A locked device still counts while its app is open.${others}`;
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

/**
 * What an item holds, as the item's page shows it: its username and website,
 * that it has a password, its other fields by name, and its notes. A secret
 * is copied by the shell and never shown here.
 */
function ItemRecord({ entry, detail, onCopyUsername, onCopy, onRemovePasskey }: { entry: VaultEntry; detail: EntryDetail | null; onCopyUsername: () => void; onCopy: (what: "password" | "field", name?: string) => void; onRemovePasskey: (credentialId: string) => void }) {
  const card = detail?.card;
  const fields = [
    ...(card ? [
      card.cardholder ? <RecordField key="cardholder" label="Cardholder name" value={card.cardholder} onCopy={() => onCopy("field", "Cardholder name")} /> : null,
      card.hasNumber ? <RecordField key="number" label="Number" value={card.numberEnding ? `•••• ${card.numberEnding}` : "••••••••"} masked onCopy={() => onCopy("field", "Number")} /> : null,
      card.expiryMonth || card.expiryYear ? <RecordField key="expiry" label="Expires" value={`${card.expiryMonth || "--"} / ${card.expiryYear || "----"}`} /> : null,
      card.hasSecurityCode ? <RecordField key="code" label="Security code" value="•••" masked onCopy={() => onCopy("field", "Security code")} /> : null,
      card.brand ? <RecordField key="brand" label="Brand" value={card.brand} /> : null,
    ] : []),
    entry.username ? <RecordField key="username" label="Username" value={entry.username} onCopy={onCopyUsername} /> : null,
    detail?.hasPassword ? <RecordField key="password" label="Password" value="••••••••••••" masked onCopy={() => onCopy("password")} /> : null,
    entry.url ? <RecordField key="url" label="Website" value={entry.url} /> : null,
    ...(detail?.fields ?? []).map((name) => <RecordField key={`field:${name}`} label={name} value="••••••••" masked onCopy={() => onCopy("field", name)} />),
  ].filter(Boolean);
  return <>{fields.length > 0 && <div className="record-card">{fields}</div>}{detail?.passkeys && detail.passkeys.length > 0 && <PasskeyList passkeys={detail.passkeys} onRemove={onRemovePasskey} />}{detail?.notes && <div className="record-card record-notes"><div className="record-field"><label>Notes</label><p>{detail.notes}</p></div></div>}</>;
}

/** A login's passkeys, by site and account; each is removed after the owner is told what that does. */
function PasskeyList({ passkeys, onRemove }: { passkeys: PasskeySummary[]; onRemove: (credentialId: string) => void }) {
  const [confirming, setConfirming] = useState<string | null>(null);
  const account = (passkey: PasskeySummary) => passkey.userDisplayName && passkey.userDisplayName !== passkey.userName ? `${passkey.userName} (${passkey.userDisplayName})` : passkey.userName || "No account name";
  return <div className="record-card passkey-list">{passkeys.map((passkey) => <div key={passkey.credentialId} className="record-field">
    <label>Passkey for {passkey.rpId}</label>
    <div><span>{account(passkey)}{passkey.createdAt > 0 && <span className="passkey-made"> · made {new Date(passkey.createdAt * 1000).toLocaleDateString(undefined, { dateStyle: "medium" })}</span>}</span>{confirming !== passkey.credentialId && <button className="field-action" title="Remove passkey" aria-label={`Remove the passkey for ${passkey.rpId}`} onClick={() => setConfirming(passkey.credentialId)}><Trash2 size={14} /></button>}</div>
    {confirming === passkey.credentialId && <div className="delete-confirm"><span>Remove this passkey on all your devices? You will no longer sign in to {passkey.rpId} with it. Its key stays in this item's history and in backups.</span><div className="form-actions"><button type="button" className="secondary" onClick={() => setConfirming(null)}>Keep</button><button type="button" className="generate-button" onClick={() => { setConfirming(null); onRemove(passkey.credentialId); }}>Remove passkey</button></div></div>}
  </div>)}</div>;
}

function RecordField({ label, value, masked, onCopy }: { label: string; value: string; masked?: boolean; onCopy?: () => void }) {
  return <div className="record-field"><label>{label}</label><div><span className={masked ? "masked" : ""}>{value}</span>{onCopy && <button className="field-action" title={`Copy ${label.toLowerCase()}`} aria-label={`Copy ${label}`} onClick={onCopy}><Copy size={14} /></button>}</div></div>;
}

/** A time a device recorded, in seconds since 1970, as this computer writes dates. */
function savedTime(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function deviceName(thisDevice: boolean, device: string): string {
  return thisDevice ? "This device" : `Device ${device}`;
}

/** An item's versions, newest first; one that is not current can be brought back. */
function HistoryPanel({ versions, onRestore }: { versions: HistoryEntry[]; onRestore: (revision: string) => void }) {
  const [confirming, setConfirming] = useState<string | null>(null);
  const said = (version: HistoryEntry) => version.deleted ? "Deleted the item" : version.first ? "Made the item" : version.merged ? "Settled a conflict between versions" : version.changed.length > 0 ? `Changed ${version.changed.join(", ")}` : "Saved without a change";
  return <>
    <p className="review-hint">Newest first. Restoring a version makes it the newest; the others stay here. Each time is by the clock of the device that saved the version; versions saved before times were kept have none.</p>
    <div className="version-list">{versions.map((version) => <div key={version.revision} className="version-card">
      <div className="version-meta"><strong>{deviceName(version.thisDevice, version.device)}{version.current ? " · current" : ""}</strong><code>{version.revision.slice(0, 10)}</code></div>
      <span className="history-time">{version.savedAt === null ? "Time not recorded" : savedTime(version.savedAt)}</span>
      <span className={version.deleted ? "version-deleted" : "history-change"}>{said(version)}</span>
      {!version.deleted && <dl><dt>Title</dt><dd>{version.title}</dd><dt>Username</dt><dd>{version.username || "—"}</dd><dt>Website</dt><dd>{version.url || "—"}</dd></dl>}
      {!version.current && !version.deleted && (confirming === version.revision
        ? <div className="form-actions"><button className="generate-button" onClick={() => onRestore(version.revision)}>Restore this version</button><button className="secondary" onClick={() => setConfirming(null)}>Keep the current</button></div>
        : <button className="secondary" onClick={() => setConfirming(version.revision)}>Restore this version…</button>)}
    </div>)}</div>
  </>;
}

/** The items deleted on any device, which can be brought back as they were. */
function DeletedPanel({ items, onRestore }: { items: DeletedEntry[]; onRestore: (item: DeletedEntry) => void }) {
  if (items.length === 0) return <p className="review-hint">Nothing has been deleted.</p>;
  return <>
    <p className="review-hint">Deleted on any of your devices, most recently first. Restoring one brings it back on all of them, as it was before it was deleted.</p>
    <div className="version-list">{items.map((item) => <div key={item.id} className="version-card">
      <div className="version-meta"><strong>{item.title}</strong><code>{kindLabel(item.kind)}</code></div>
      <span className="history-change">{[item.username, item.url].filter(Boolean).join(" · ") || "—"}</span>
      <span className="version-deleted">Deleted on {item.thisDevice ? "this device" : `device ${item.device}`}{item.deletedAt === null ? "" : ` · ${savedTime(item.deletedAt)}`}</span>
      <button className="generate-button" onClick={() => onRestore(item)}>Restore</button>
    </div>)}</div>
  </>;
}

/** What the owner sets on this computer. */
function SettingsPanel({ minutes, locked, onChange, onNotice }: { minutes: number; locked: boolean; onChange: (minutes: number) => void; onNotice: (text: string) => void }) {
  return <div className="entry-form">
    <label>Lock the vault after<select aria-label="Lock the vault after" value={minutes} onChange={(event) => onChange(Number(event.target.value))}>{AUTO_LOCK_CHOICES.map((choice) => <option key={choice} value={choice}>{minutesText(choice)} without activity</option>)}</select></label>
    <p className="review-hint">Hiding or covering the window leaves the vault unlocked for this long too. The computer going to sleep and the screen locking lock it at once, whatever this says. This setting stays on this computer; your other devices keep their own.</p>
    {locked ? <p className="review-hint">Unlock the vault to change this device's password.</p> : <ChangePassword onNotice={onNotice} />}
  </div>;
}

/** This device's password changed, given the current one. */
function ChangePassword({ onNotice }: { onNotice: (text: string) => void }) {
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [working, setWorking] = useState(false);

  async function change() {
    if (password.length < 12) { onNotice("Use at least 12 characters for this device password"); return; }
    if (password !== again) { onNotice("The two passwords differ"); return; }
    setWorking(true);
    try {
      await bridge.changePassword(current, password);
      setCurrent("");
      setPassword("");
      setAgain("");
      onNotice("Password changed · unlock with the new one from now on");
    } catch (error) {
      const code = (error as { code?: string } | null)?.code;
      onNotice(code === "invalid_credentials" ? "That is not this device's current password · nothing was changed" : commandMessage(error, "The password was not changed"));
    } finally {
      setWorking(false);
    }
  }

  return <>
    <h3 className="settings-heading">This device's password</h3>
    <label>Current password<input aria-label="Current device password" type="password" value={current} disabled={working} onChange={(event) => setCurrent(event.target.value)} /></label>
    <label>New password<input aria-label="New device password" type="password" value={password} disabled={working} onChange={(event) => setPassword(event.target.value)} /></label>
    <label>New password again<input aria-label="New device password again" type="password" value={again} disabled={working} onChange={(event) => setAgain(event.target.value)} /></label>
    <div className="form-actions"><button className="generate-button" disabled={working || !current || !password || !again} onClick={() => void change()}>{working ? "Changing…" : "Change this device's password"}</button></div>
    <p className="review-hint">Only this device's password changes: your other devices keep their own, and the recovery key and backups open the vault as before.</p>
  </>;
}

const importSources: { format: ImportFormat; name: string; detail: string }[] = [
  { format: "bitwarden", name: "Bitwarden", detail: "An unencrypted JSON export" },
  { format: "chrome", name: "Chrome", detail: "Passwords exported as CSV" },
  { format: "firefox", name: "Firefox", detail: "Logins exported as CSV" },
];

/**
 * Brings in another app's export: the owner picks the file in the system's
 * dialog, which the shell reads, sees what it would add, and confirms.
 */
function ImportPanel({ onImported, onNotice }: { onImported: (added: number) => void; onNotice: (text: string) => void }) {
  const [summary, setSummary] = useState<ImportSummary | null>(null);
  const [busy, setBusy] = useState(false);
  async function choose(format: ImportFormat) {
    setBusy(true);
    try {
      const read = await bridge.chooseImport(format);
      if (read) setSummary(read);
    } catch (error) {
      onNotice(commandMessage(error, "That file could not be read"));
    } finally {
      setBusy(false);
    }
  }
  async function confirm() {
    setBusy(true);
    try {
      onImported(await bridge.confirmImport());
    } catch (error) {
      onNotice(commandMessage(error, "Nothing was imported"));
      setBusy(false);
    }
  }
  if (!summary) {
    return <div className="entry-form">
      <p className="review-hint">Export your logins from the other app first, then choose the export here. It is read on this computer, and nothing is added until you confirm.</p>
      <div className="import-sources">{importSources.map((source) => <button key={source.format} className="version-card import-source" disabled={busy} onClick={() => void choose(source.format)}><strong>{source.name}</strong><span>{source.detail}</span></button>)}</div>
    </div>;
  }
  const kinds = [[summary.logins, "login"], [summary.notes, "secure note"], [summary.cards, "card"], [summary.identities, "identity"]] as const;
  const described = kinds.filter(([count]) => count > 0).map(([count, kind]) => `${count} ${kind === "identity" && count !== 1 ? "identities" : count === 1 ? kind : `${kind}s`}`).join(", ");
  return <div className="entry-form" aria-label="What the import adds">
    <div className="version-card">
      <div className="version-meta"><strong>{summary.file}</strong></div>
      <span className="import-count">{summary.items} {summary.items === 1 ? "item" : "items"} to add: {described}</span>
      {summary.already > 0 && <span className="review-hint">{summary.already} of them {summary.already === 1 ? "looks like an item" : "look like items"} you already have (the same website and username). {summary.already === 1 ? "It is" : "They are"} added all the same; delete what you do not need.</span>}
      {summary.warnings.length > 0 && <details className="import-skipped"><summary>{summary.warnings.length} {summary.warnings.length === 1 ? "entry was" : "entries were"} skipped</summary><ul>{summary.warnings.slice(0, 50).map((warning, index) => <li key={index}>Entry {warning.row}: {warning.message}</li>)}{summary.warnings.length > 50 && <li>and {summary.warnings.length - 50} more</li>}</ul></details>}
    </div>
    <p className="review-hint">The export holds your passwords unencrypted. Once they are here, delete it and empty the trash.</p>
    <div className="form-actions"><button className="generate-button" disabled={busy} onClick={() => void confirm()}>Add {summary.items} {summary.items === 1 ? "item" : "items"}</button><button className="secondary" disabled={busy} onClick={() => { setSummary(null); void bridge.cancelImport().catch(() => {}); }}>Choose another</button></div>
  </div>;
}

function commandMessage(error: unknown, fallback: string): string {
  const code = (error as { code?: string } | null)?.code;
  if (code === "conflict") return "This item changed since you opened it · reopen to edit";
  if (code === "unresolved") return "This item has conflicting versions · review them first";
  if (code === "missing_parent") return "That change builds on one this device has not received yet · sync first";
  if (code === "not_confirmed") return "The pairing was declined";
  if (code === "pin_mismatch") return "That device is not the one in the invitation";
  if (code === "invitation_expired") return "The invitation has expired · create a new one";
  if (code === "invalid_invitation") return "That is not a valid invitation";
  if (code === "invalid_relay_code") return "That is not a relay code · copy the whole code the relay printed";
  if (code === "quorum_unavailable") return "Not enough of your devices are reachable · most of them must be online to add or remove one · nothing was changed";
  if (code === "invalid_credentials") return "That password was rejected · nothing was changed";
  if (code === "no_archive") return `${fallback} · it is no longer there or no longer open`;
  if (code === "only_device") return "This is the vault's only device · there is no other vault to join";
  if (code === "joining") return "Finish or cancel joining first";
  if (code === "not_removed") return "Only a device that was removed from its vault can be reset";
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
  if (code === "invalid_import") return `That is not such an export · ${(error as { message?: string }).message ?? "it could not be read"}`;
  if (code === "no_import") return "Choose an export first";
  if (code === "no_password") return "This item has no password";
  if (code === "clipboard") return "The clipboard is not available · nothing was copied";
  if (code === "invalid_setting") return "That is not one of the choices";
  return fallback;
}

const entryKinds: { value: EntryKind; label: string }[] = [
  { value: "login", label: "Login" },
  { value: "secure_note", label: "Secure note" },
  { value: "identity", label: "Identity" },
  { value: "card", label: "Card" },
];

function EntryEditor({ detail, generator, onGeneratorChoice, onCancel, onSave, onDelete }: { detail?: EntryDetail; generator: GeneratorChoice | null; onGeneratorChoice: (choice: GeneratorChoice) => void; onCancel: () => void; onSave: (input: EntryInput) => Promise<void>; onDelete?: () => Promise<void> }) {
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [title, setTitle] = useState(detail?.title ?? "");
  const [kind, setKind] = useState<EntryKind>(detail?.kind ?? "login");
  const [username, setUsername] = useState(detail?.username ?? "");
  const [url, setUrl] = useState(detail?.url ?? "");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  // The password the generator made, until the owner types over it.
  const [made, setMade] = useState(false);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  /** The owner set the password, which a password still being made then leaves alone. */
  const passwordSet = useRef(false);
  const prefilled = useRef(false);
  const [totpSecret, setTotpSecret] = useState("");
  const [removeTotp, setRemoveTotp] = useState(false);
  const [notes, setNotes] = useState(detail?.notes ?? "");
  const [favorite, setFavorite] = useState(detail?.favorite ?? false);
  const [saving, setSaving] = useState(false);
  const stored = detail?.card;
  const [cardholder, setCardholder] = useState(stored?.cardholder ?? "");
  const [number, setNumber] = useState("");
  const [showNumber, setShowNumber] = useState(false);
  const [expiryMonth, setExpiryMonth] = useState(stored?.expiryMonth ?? "");
  const [expiryYear, setExpiryYear] = useState(stored?.expiryYear ?? "");
  const [securityCode, setSecurityCode] = useState("");
  const [removeCode, setRemoveCode] = useState(false);
  // Untouched, the brand is the one a new number names, or else the stored one.
  const [brand, setBrand] = useState<string | null>(null);
  const detected = cardBrand(number);
  const numberSlip = cardDigits(number) !== null && !passesCardCheck(number);

  // A new item opens with a password made for it, shown, unless the owner
  // set one before it came.
  useEffect(() => {
    if (detail || !generator || prefilled.current) return;
    prefilled.current = true;
    void bridge.generatePassword(generator).then((value) => {
      if (passwordSet.current) return;
      setPassword(value); setShowPassword(true); setMade(true);
    }).catch(() => {});
  }, [detail, generator]);
  function setPasswordTo(value: string, generated: boolean) {
    passwordSet.current = true;
    setPassword(value); setMade(generated);
    if (generated) setShowPassword(true);
  }
  async function generate() { if (generator) setPasswordTo(await bridge.generatePassword(generator), true); }
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!title.trim() || saving) return;
    setSaving(true);
    await onSave({
      title: title.trim(), kind, username, url: url.trim(), notes, favorite,
      // Blank password/TOTP fields keep the stored value. Only a login or
      // an identity shows a password, and keeps one.
      password: password && (kind === "login" || kind === "identity") ? password : undefined,
      totpSecret: removeTotp ? "" : totpSecret.trim() ? totpSecret : undefined,
      // Blank number and code keep the stored ones too.
      card: kind === "card" ? {
        cardholder, expiryMonth, expiryYear,
        brand: brand ?? undefined,
        number: number.trim() ? number : undefined,
        securityCode: removeCode ? "" : securityCode.trim() ? securityCode : undefined,
      } : undefined,
    });
    setSaving(false);
  }

  return <form className="entry-form" onSubmit={submit}>
    <label>Title<input autoFocus value={title} onChange={(event) => setTitle(event.target.value)} placeholder="e.g. GitHub" /></label>
    <label>Type<select value={kind} onChange={(event) => setKind(event.target.value as EntryKind)}>{entryKinds.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
    {kind === "card" && <>
      <label>Cardholder name<input value={cardholder} onChange={(event) => setCardholder(event.target.value)} autoComplete="off" /></label>
      <label>Number<div className="field-row"><input type={showNumber ? "text" : "password"} inputMode="numeric" value={number} onChange={(event) => setNumber(event.target.value)} placeholder={stored?.hasNumber ? `Unchanged${stored.numberEnding ? ` (•••• ${stored.numberEnding})` : ""}` : ""} autoComplete="off" /><button type="button" className="icon-button" title={showNumber ? "Hide" : "Show"} onClick={() => setShowNumber(!showNumber)}>{showNumber ? <EyeOff size={15} /> : <Eye size={15} />}</button></div></label>
      {numberSlip && <p className="field-hint">This number fails a card number's check: a digit may be mistyped. It is saved as typed.</p>}
      <div className="field-pair">
        <label>Expiry month<select value={expiryMonth} onChange={(event) => setExpiryMonth(event.target.value)}><option value="">--</option>{Array.from({ length: 12 }, (_, index) => String(index + 1).padStart(2, "0")).map((month) => <option key={month} value={month}>{month}</option>)}{expiryMonth && !/^(0[1-9]|1[0-2])$/.test(expiryMonth) && <option value={expiryMonth}>{expiryMonth}</option>}</select></label>
        <label>Expiry year<input value={expiryYear} onChange={(event) => setExpiryYear(event.target.value)} inputMode="numeric" placeholder="YYYY" autoComplete="off" /></label>
      </div>
      <label>Security code<input type="password" inputMode="numeric" value={securityCode} disabled={removeCode} onChange={(event) => setSecurityCode(event.target.value)} placeholder={stored?.hasSecurityCode ? "Unchanged" : ""} autoComplete="off" /></label>
      {stored?.hasSecurityCode && <label className="check-row"><input type="checkbox" checked={removeCode} onChange={(event) => setRemoveCode(event.target.checked)} /> Remove security code</label>}
      <label>Brand<input value={brand ?? (number.trim() ? detected ?? "" : stored?.brand ?? "")} onChange={(event) => setBrand(event.target.value)} placeholder="From the number" list="card-brands" autoComplete="off" /></label>
      <datalist id="card-brands">{["Visa", "Mastercard", "Amex", "JCB", "UnionPay", "Discover", "Diners Club"].map((name) => <option key={name} value={name} />)}</datalist>
    </>}
    {kind !== "secure_note" && kind !== "card" && <>
      <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" /></label>
      <label>Website<input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://" autoComplete="off" /></label>
      <label>Password<div className="field-row"><input type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPasswordTo(event.target.value, false)} placeholder={detail?.hasPassword ? "Unchanged" : ""} autoComplete="new-password" /><button type="button" className="icon-button" title={showPassword ? "Hide" : "Show"} onClick={() => setShowPassword(!showPassword)}>{showPassword ? <EyeOff size={15} /> : <Eye size={15} />}</button>{password && <button type="button" className="icon-button" title="Clear" onClick={() => setPasswordTo("", false)}><Eraser size={15} /></button>}<button type="button" className="icon-button" title="Generate" onClick={() => void generate()} disabled={!generator}><Sparkles size={15} /></button><button type="button" className="icon-button" title="Generator options" aria-expanded={generatorOpen} onClick={() => setGeneratorOpen(!generatorOpen)} disabled={!generator}><SlidersHorizontal size={15} /></button></div></label>
      {made && <p className="field-note">Made for this item with the generator's choice. Type over it, or clear it.</p>}
      {generatorOpen && generator && <Generator choice={generator} onChoice={onGeneratorChoice} onUse={(value) => { setPasswordTo(value, true); setGeneratorOpen(false); }} />}
      <label>TOTP secret<input type="password" value={totpSecret} disabled={removeTotp} onChange={(event) => setTotpSecret(event.target.value)} placeholder={detail?.hasTotp ? "Unchanged" : "Base32 secret (optional)"} autoComplete="off" /></label>
      {detail?.hasTotp && <label className="check-row"><input type="checkbox" checked={removeTotp} onChange={(event) => setRemoveTotp(event.target.checked)} /> Remove one-time code</label>}
    </>}
    <label>Notes<textarea rows={kind === "secure_note" ? 7 : 3} value={notes} onChange={(event) => setNotes(event.target.value)} /></label>
    <label className="check-row"><input type="checkbox" checked={favorite} onChange={(event) => setFavorite(event.target.checked)} /> Favorite</label>
    {confirmingDelete
      ? <div className="delete-confirm"><span>Delete this item on all your devices? Its earlier versions stay in the vault's history and in backups.</span><div className="form-actions"><button type="button" className="secondary" onClick={() => setConfirmingDelete(false)}>Keep</button><button type="button" className="generate-button" onClick={() => void onDelete?.()}>Delete</button></div></div>
      : <div className="form-actions">{onDelete && <button type="button" className="secondary" onClick={() => setConfirmingDelete(true)}>Delete…</button>}<button type="button" className="secondary" onClick={onCancel}>Cancel</button><button type="submit" className="generate-button" disabled={!title.trim() || saving}>{detail ? "Save changes" : "Create item"}</button></div>}
  </form>;
}

/**
 * The generator: the owner's choice of length and of characters, kept on
 * this device, and a password made with it, made again at each change. From
 * the sidebar, `onCopy` copies it; in the editor, `onUse` puts it in the
 * password field.
 */
function Generator({ choice, onChoice, onCopy, onUse }: { choice: GeneratorChoice; onChoice: (choice: GeneratorChoice) => void; onCopy?: (value: string) => void; onUse?: (value: string) => void }) {
  const [length, setLength] = useState(choice.length);
  const [value, setValue] = useState("");
  const shown = { ...choice, length };
  async function generate() {
    try { setValue(await bridge.generatePassword(shown)); } catch { setValue(""); }
  }
  useEffect(() => { void generate(); }, [length, choice.lowercase, choice.uppercase, choice.digits, choice.symbols, choice.avoidLookAlike]);
  // The length is kept once the slider rests, or the generator closes.
  const latest = useRef({ choice, length, onChoice });
  latest.current = { choice, length, onChoice };
  useEffect(() => {
    if (length === choice.length) return;
    const timer = setTimeout(() => onChoice({ ...choice, length }), 300);
    return () => clearTimeout(timer);
  }, [length]);
  useEffect(() => () => {
    const { choice, length, onChoice } = latest.current;
    if (length !== choice.length) onChoice({ ...choice, length });
  }, []);
  const kinds = [["uppercase", "A–Z"], ["lowercase", "a–z"], ["digits", "0–9"], ["symbols", "!@#$"]] as const;
  const chosen = kinds.filter(([kind]) => choice[kind]).length;
  return <div className="generator">
    <div className="generated-value"><code>{value || "Generate a fresh password"}</code>{onCopy && <button type="button" title="Copy" disabled={!value} onClick={() => onCopy(value)}><Copy size={16} /></button>}</div>
    <label className="range-label">Length <strong>{length}</strong></label>
    <input type="range" aria-label="Length" min="8" max="64" value={length} onChange={(event) => setLength(Number(event.target.value))} />
    {/* The last kind chosen stays: a password needs one. */}
    <div className="generator-options">{kinds.map(([kind, label]) => <label key={kind} className="check-row"><input type="checkbox" checked={choice[kind]} disabled={choice[kind] && chosen === 1} onChange={(event) => onChoice({ ...shown, [kind]: event.target.checked })} /> {label}</label>)}</div>
    <label className="check-row generator-look-alike"><input type="checkbox" checked={choice.avoidLookAlike} onChange={(event) => onChoice({ ...shown, avoidLookAlike: event.target.checked })} /> Avoid look-alikes <code>l I 1 O 0</code></label>
    <div className="generator-actions"><button type="button" className="generate-button" onClick={() => void generate()}><Sparkles size={16} /> Generate new password</button>{onUse && <button type="button" className="generate-button" disabled={!value} onClick={() => onUse(value)}>Use this password</button>}</div>
  </div>;
}

export default App;
