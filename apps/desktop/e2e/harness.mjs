// What the end-to-end tests share: the real desktop app, built by
// `tauri build --debug --no-bundle`, driven through its own window by
// tauri-driver and WebKitWebDriver on Linux, on a virtual display. Each
// instance is a device of its own: its own home folder, so its own vault
// and files, and its own tauri-driver. The system's file dialogs are not
// part of the page, so they are answered with xdotool. Run in a container
// by `scripts/test-linux-app.sh`; nothing here runs on macOS, which has no
// driver for its web view.

import { execFileSync, spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Builder, By, Capabilities, Key, until } from "selenium-webdriver";

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = process.env.OSM_APP ?? path.resolve(here, "../src-tauri/target/debug/open-secret-manager");
/** Long, because a debug build in a container is slow to start and to unlock. */
export const PATIENCE_MS = 60_000;

/** A scratch folder for one test file's devices and files. */
export const scratch = mkdtempSync(path.join(os.tmpdir(), "osm-e2e-"));
/** Where a wait that ran out leaves what the window showed (`OSM_E2E_TRACES`, or the scratch folder). */
const traces = process.env.OSM_E2E_TRACES ?? scratch;
mkdirSync(traces, { recursive: true });

let nextPort = 4444;

async function listening(port) {
  for (let tries = 0; tries < 100; tries++) {
    const open = await new Promise((resolve) => {
      const socket = net.connect(port, "127.0.0.1", () => { socket.end(); resolve(true); });
      socket.on("error", () => resolve(false));
    });
    if (open) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`nothing listens on ${port}`);
}

/**
 * Starts the app as a device named `name`, with a home folder of its own,
 * and returns its window to drive. `quit` closes the app and its driver.
 */
export async function device(name) {
  const home = path.join(scratch, name);
  mkdirSync(home, { recursive: true });
  const launcher = path.join(scratch, `${name}.sh`);
  writeFileSync(launcher, `#!/bin/sh\nexport HOME='${home}'\nexec '${APP}' "$@"\n`);
  chmodSync(launcher, 0o755);
  const port = nextPort;
  nextPort += 2;
  const driver = spawn("tauri-driver", ["--port", String(port), "--native-port", String(port + 1)], { stdio: "ignore" });
  await listening(port);
  const capabilities = new Capabilities();
  capabilities.setBrowserName("wry");
  capabilities.set("tauri:options", { application: launcher });
  const window = await new Builder().withCapabilities(capabilities).usingServer(`http://127.0.0.1:${port}/`).build();
  await window.wait(until.elementLocated(By.css(".app-shell")), PATIENCE_MS);
  window.osmName = name;
  return {
    name,
    home,
    window,
    async quit() {
      await window.quit().catch(() => {});
      driver.kill();
    },
  };
}

const quoted = (text) => (text.includes('"') ? `'${text}'` : `"${text}"`);

/** The visible button whose text is `text`, or contains it with `{ partly: true }`. */
export async function button(window, text, { partly = false, within = "" } = {}) {
  const test = partly ? `contains(normalize-space(.), ${quoted(text)})` : `normalize-space(.) = ${quoted(text)}`;
  const found = await window.wait(until.elementLocated(By.xpath(`${within}//button[${test}]`)), PATIENCE_MS);
  await window.wait(until.elementIsVisible(found), PATIENCE_MS);
  await window.wait(until.elementIsEnabled(found), PATIENCE_MS);
  return found;
}

export async function press(window, text, options) {
  await (await button(window, text, options)).click();
}

/** Types `text` into the field named `label`, replacing what it held. */
export async function fill(window, label, text) {
  const field = await window.wait(until.elementLocated(By.css(`[aria-label=${quoted(label)}]`)), PATIENCE_MS);
  await window.wait(until.elementIsVisible(field), PATIENCE_MS);
  await field.clear();
  await field.sendKeys(text);
}

/** Types into the field labelled `label` in the open dialog (an editor's form). */
export async function fillIn(window, label, text) {
  const field = await window.wait(
    until.elementLocated(By.xpath(`//div[contains(@class, "generator-modal")]//label[starts-with(normalize-space(.), ${quoted(label)})]//*[self::input or self::textarea]`)),
    PATIENCE_MS,
  );
  await field.clear();
  await field.sendKeys(text);
}

/**
 * Waits until the window shows `text`, and returns the innermost element
 * whose text holds it (React can split one sentence into several text
 * nodes).
 */
export async function shows(window, text, timeout = PATIENCE_MS) {
  const holds = `contains(normalize-space(.), ${quoted(text)})`;
  try {
    return await window.wait(until.elementLocated(By.xpath(`//body//*[${holds} and not(*[${holds}])]`)), timeout);
  } catch (error) {
    throw new Error(`${text} never showed; the window showed: ${await leaveTrace(window, "never-showed")}`, { cause: error });
  }
}

/**
 * Saves what the window shows, beside the scratch folder's devices, and
 * returns its text, for a wait that ran out.
 */
export async function leaveTrace(window, what) {
  const file = path.join(traces, `${window.osmName ?? "window"}-${what}-${Date.now()}.png`);
  try {
    writeFileSync(file, await window.takeScreenshot(), "base64");
  } catch {}
  const body = await window.findElement(By.css("body")).getAttribute("innerText").catch(() => "");
  return `${body.replace(/\s+/g, " ").slice(0, 600)} (${file})`;
}

/**
 * The text of the first element `css` matches, once there is one, as the
 * page holds it: WebDriver's own reading is empty for text it judges not
 * shown, as an invitation cut short with an ellipsis is.
 */
export async function textOf(window, css) {
  const element = await window.wait(until.elementLocated(By.css(css)), PATIENCE_MS);
  await window.wait(until.elementIsVisible(element), PATIENCE_MS);
  await window.wait(async () => (await element.getAttribute("textContent")).trim() !== "", PATIENCE_MS);
  return (await element.getAttribute("textContent")).trim();
}

/** The titles of the items the list shows, as the page holds them. */
export async function titles(window) {
  const rows = await window.findElements(By.css(".entry-row strong"));
  return Promise.all(rows.map(async (row) => (await row.getAttribute("textContent")).trim()));
}

/** Makes a vault on a device without one; returns its recovery key, once confirmed stored. */
export async function createVault(window, password) {
  await fill(window, "Vault password", password);
  await press(window, "Create", { partly: true });
  const key = await textOf(window, ".recovery-card code");
  await press(window, "I stored it");
  return key;
}

/** Adds a login through the window's editor. */
export async function addLogin(window, title, username, password) {
  await press(window, "New item", { partly: true });
  await fillIn(window, "Title", title);
  await fillIn(window, "Username", username);
  await fillIn(window, "Password", password);
  await press(window, "Create item");
  await window.wait(until.elementLocated(By.xpath(`//*[contains(@class, "entry-row")]//strong[normalize-space(.) = ${quoted(title)}]`)), PATIENCE_MS);
}

/** Opens the Devices dialog from the window's footer. */
export async function openDevices(window) {
  await press(window, "Devices", { within: "//footer" });
  await shows(window, "Devices and sync");
}

function xdotool(...args) {
  return execFileSync("xdotool", args, { encoding: "utf8" }).trim();
}

/**
 * Answers the system's file dialog titled `title` with `file`: types its
 * path where GTK's chooser takes one, and confirms. The dialog is not part
 * of the page, so WebDriver cannot reach it.
 */
export async function answerFileDialog(title, file) {
  let dialog = "";
  for (let tries = 0; tries < 300 && !dialog; tries++) {
    try {
      dialog = xdotool("search", "--onlyvisible", "--name", title).split("\n")[0];
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
  if (!dialog) throw new Error(`no dialog titled ${title}`);
  // No window manager runs on the virtual display: the dialog is given the
  // keyboard itself, and keys go through the X server's test input, which
  // GTK takes as typed (it ignores events sent to a window).
  xdotool("windowfocus", "--sync", dialog);
  // The location field takes a whole path, in an open dialog after Ctrl+L
  // and in a save dialog as the name.
  xdotool("key", "ctrl+l");
  xdotool("key", "ctrl+a");
  xdotool("type", "--delay", "20", file);
  await new Promise((resolve) => setTimeout(resolve, 300));
  xdotool("key", "Return");
}

export { By, Key, until };
