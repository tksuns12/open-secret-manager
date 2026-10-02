// What the browser tests share: a scratch home folder with a vault and the
// stand-in for the desktop app, test pages served over https under made-up
// names, and a headless Chromium with the built extension and the native
// messaging host registered for it.
//
// Nothing here is mocked between the page and the vault: the extension is
// the built one, the host is the real binary, started by the browser, and
// the stand-in (`osm-fill`) runs the app's own session code on a real
// vault. Only the owner is played, by commands to the stand-in.

import { execFileSync, spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "../../..");
const built = (name) => path.join(repository, "target/debug", name);

export const HOST_NAME = "org.opensecretmanager.native";
export const EXTENSION_ID = "hjgekjgkjnakgmiopldddikdkcjhnmge";
const PASSWORD = "correct horse battery staple";
// Long, because macOS can hold a newly built or newly written program for
// tens of seconds before its first start.
const PATIENCE_MS = 90_000;

/** The pages the tests open. Every name ends in `.test` and resolves to this machine. */
const loginForm = (title) => `<!doctype html><meta charset="utf-8"><title>${title}</title>
<form id="login" action="/submitted" method="post">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button id="submit" type="submit">Sign in</button>
</form>
<script>
  // What a page would notice: input events, and whether the form was sent.
  window.seen = { events: [], submitted: false };
  for (const input of document.querySelectorAll("input")) {
    for (const kind of ["input", "change", "keydown"]) input.addEventListener(kind, () => window.seen.events.push(kind + ":" + input.id));
  }
  document.getElementById("login").addEventListener("submit", () => { window.seen.submitted = true; });
</script>`;

function respond(request, response) {
  const url = new URL(request.url, "https://placeholder.test");
  const send = (body) => { response.writeHead(200, { "content-type": "text/html; charset=utf-8" }); response.end(body); };
  switch (url.pathname) {
    case "/login": return send(loginForm("Sign in"));
    case "/next": return send(loginForm("Another page of the same site"));
    case "/empty": return send(`<!doctype html><title>Nothing to fill</title><p>No form here.</p>`);
    // A page with no form of its own that shows another site's form in a frame.
    case "/framing": return send(`<!doctype html><title>Framing page</title><p>The form below belongs to another site.</p><iframe id="inner" src="https://login.test/login" width="400" height="200"></iframe>`);
    // A page with its own form and another site's form in a frame.
    case "/both": return send(loginForm("Outer form") + `<iframe id="inner" src="https://login.test/login" width="400" height="200"></iframe>`);
    // A form that asks for the user name only.
    case "/name-first": return send(`<!doctype html><title>Name first</title><form id="login"><input id="username" name="email" type="email" autocomplete="username"><button type="submit">Next</button></form><script>window.seen = { submitted: false }; document.getElementById("login").addEventListener("submit", () => { window.seen.submitted = true; });</script>`);
    case "/submitted": return send(`<!doctype html><title>Submitted</title>`);
    default: response.writeHead(404); response.end();
  }
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}

/** A running process whose output lines can be awaited. */
class Lines {
  constructor(child) {
    this.child = child;
    this.lines = [];
    this.waiters = [];
    let rest = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      const parts = (rest + chunk).split("\n");
      rest = parts.pop();
      for (const line of parts) {
        this.lines.push(line);
        this.waiters.shift()?.();
      }
    });
  }

  /** The next line, whatever it is. */
  async line() {
    const deadline = Date.now() + PATIENCE_MS;
    while (this.lines.length === 0) {
      const left = deadline - Date.now();
      if (left <= 0) throw new Error("the stand-in printed nothing more");
      await new Promise((resolve) => { const timer = setTimeout(resolve, left); this.waiters.push(() => { clearTimeout(timer); resolve(); }); });
    }
    return this.lines.shift();
  }

  /** The rest of the next line that starts with `keyword`; lines before it are dropped. */
  async expect(keyword) {
    for (;;) {
      const line = await this.line();
      if (line === keyword) return "";
      if (line.startsWith(keyword + " ")) return line.slice(keyword.length + 1);
    }
  }

  /** Asserts that nothing is printed for a while. */
  async quiet(ms = 700) {
    await new Promise((resolve) => setTimeout(resolve, ms));
    if (this.lines.length > 0) throw new Error(`the stand-in printed: ${this.lines.join(" | ")}`);
  }

  say(command) { this.child.stdin.write(command + "\n"); }
}

/**
 * Sets everything up. `logins` are `[title, address]` pairs put into the
 * vault; `host` is the program the browser starts as the native messaging
 * host (the real one unless a test gives another); `standIn` are the
 * options `osm-fill serve` is started with, or null for no desktop session.
 */
export async function start({ logins = [], fakeHost = false, standIn = ["ask"], registerHost = true, forged = false, appHome = null } = {}) {
  // Short, because a socket's path has to fit in about a hundred bytes.
  const home = mkdtempSync("/tmp/osm");
  const closers = [() => rmSync(home, { recursive: true, force: true })];
  // With `appHome`, the desktop app itself is running for that home folder:
  // the browser and the host use it, and nothing stands in for the app.
  if (appHome) return browse({ home, accountHome: appHome, closers, fakeHost, registerHost, forged, app: null, items: {}, vault: null });
  const env = { ...process.env, HOME: home, OSM_PASSWORD: PASSWORD };
  delete env.XDG_DATA_HOME;

  // The vault and the stand-in for the app, where the app would have them.
  const dataFolder = process.platform === "darwin" ? path.join(home, "Library/Application Support") : path.join(home, ".local/share");
  const appFolder = path.join(dataFolder, "OpenSecretManager");
  mkdirSync(appFolder, { recursive: true });
  const vault = path.join(appFolder, "vault.sqlite3");
  const fill = (...args) => execFileSync(built("osm-fill"), args, { env, encoding: "utf8" }).trim();
  fill("create", vault);
  const items = {};
  for (const [title, address] of logins) {
    items[title] = fill("add", vault, title, `${title}@example.test`, `${title} password`, address).split(" ")[1];
  }
  let app = null;
  if (standIn) {
    const child = spawn(built("osm-fill"), ["serve", vault, "-", ...standIn], { env, stdio: ["pipe", "pipe", "inherit"] });
    closers.push(() => child.kill());
    app = new Lines(child);
    await app.expect("LISTENING");
  }
  return browse({ home, accountHome: home, closers, fakeHost, registerHost, forged, app, items, vault });
}

/** The pages, and a browser with the extension, for the account whose home folder is `accountHome`. */
async function browse({ home, accountHome, closers, fakeHost, registerHost, forged, app, items, vault }) {
  const env = { ...process.env, HOME: accountHome };
  delete env.XDG_DATA_HOME;

  // The pages: one server for https under every name, one for plain http.
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=login.test",
    "-addext", "subjectAltName=DNS:login.test,DNS:*.login.test,DNS:framing.test,DNS:other.test",
    "-keyout", path.join(home, "key.pem"), "-out", path.join(home, "cert.pem")], { stdio: "ignore" });
  const secure = https.createServer({ key: readFileSync(path.join(home, "key.pem")), cert: readFileSync(path.join(home, "cert.pem")) }, respond);
  const plain = http.createServer(respond);
  const [securePort, plainPort] = [await listen(secure), await listen(plain)];
  closers.push(() => secure.close(), () => plain.close());

  // The browser's own folder, with the host registered in it as the app's
  // Browser panel would register it in a real browser's folder.
  const profile = path.join(home, "profile");
  let host = built("osm-native-host");
  if (fakeHost) {
    // A program that answers wrongly on purpose, in the real host's place.
    // It is started as the file it is, not through a script written for
    // each run: macOS holds the first start of a file it has not seen
    // until it has checked it, which can take many seconds.
    host = path.join(here, "fake-host.mjs");
  }
  if (registerHost) {
    mkdirSync(path.join(profile, "NativeMessagingHosts"), { recursive: true });
    writeFileSync(path.join(profile, "NativeMessagingHosts", `${HOST_NAME}.json`), JSON.stringify({
      name: HOST_NAME,
      description: "Open Secret Manager native messaging host",
      path: host,
      type: "stdio",
      allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
    }));
  }
  const extension = path.resolve(here, "../dist/chromium");
  const extensions = [extension, ...(forged ? [withoutKey(home)] : [])].join(",");
  const context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    env,
    ignoreHTTPSErrors: true,
    args: [
      `--disable-extensions-except=${extensions}`,
      `--load-extension=${extensions}`,
      // Lets the tests press the extension's toolbar button, which is what
      // gives the extension leave to act on the tab, as a real press does.
      "--enable-unsafe-extension-debugging",
      // Every `.test` name is this machine: plain.test over http, the rest
      // over https, whatever port the address names.
      `--host-resolver-rules=MAP plain.test 127.0.0.1:${plainPort}, MAP *.test 127.0.0.1:${securePort}`,
    ],
  });
  closers.push(() => context.close());

  const worker = async (id = EXTENSION_ID) => {
    const found = () => context.serviceWorkers().find((candidate) => candidate.url().startsWith(`chrome-extension://${id}/`));
    const deadline = Date.now() + PATIENCE_MS;
    while (!found()) {
      if (Date.now() > deadline) throw new Error(`the extension ${id} did not start`);
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return found();
  };
  // A press that comes before the extension has finished starting, right
  // after it was put into a new browser, is lost. Wait until it listens.
  const listening = async (id) => {
    const deadline = Date.now() + PATIENCE_MS;
    while (!(await (await worker(id)).evaluate(() => chrome.action.onClicked.hasListeners()))) {
      if (Date.now() > deadline) throw new Error(`the extension ${id} does not listen for its button`);
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  };
  await listening(EXTENSION_ID);
  // The other extension, if one was loaded, is whichever is not ours.
  let forgedId = null;
  if (forged) {
    const deadline = Date.now() + PATIENCE_MS;
    while (!forgedId) {
      const other = context.serviceWorkers().map((candidate) => new URL(candidate.url()).host).find((id) => id !== EXTENSION_ID);
      if (other) { forgedId = other; await listening(other); }
      else if (Date.now() > deadline) throw new Error("the other extension did not start");
      else await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  return {
    home, context, app, items, vault, forgedId,
    /** Tells the fake host how to answer the next request. */
    plan(mode) { writeFileSync(path.join(home, "fake-host-plan.json"), JSON.stringify({ mode })); },
    /** What the fake host was sent, one message per entry, and `closed` when the browser let it go. */
    hostLog() {
      const file = path.join(home, "fake-host.log");
      return existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean) : [];
    },
    worker,
    async open(address) {
      const page = await context.newPage();
      await page.goto(address);
      return page;
    },
    /** Presses the extension's toolbar button for the tab showing `page`, as the owner would. */
    async press(page, id = EXTENSION_ID) {
      await page.bringToFront();
      // The press is addressed to the tab, which the browser knows under
      // another name than the page inside it; the tab is found by its
      // address, so tests give each tab its own.
      const session = await context.browser().newBrowserCDPSession();
      const { targetInfos } = await session.send("Target.getTargets", { filter: [{ type: "tab" }] });
      const tabs = targetInfos.filter((tab) => tab.url === page.url());
      if (tabs.length !== 1) throw new Error(`${tabs.length} tabs show ${page.url()}`);
      await session.send("Extensions.triggerAction", { id, targetId: tabs[0].targetId });
      await session.detach();
    },
    /** What the toolbar button says for the tab showing `page`. */
    async status(page, id = EXTENSION_ID) {
      // The extension is not told tabs' addresses, so the tab is found as
      // the one in front in the page's window.
      await page.bringToFront();
      const session = await context.newCDPSession(page);
      const { windowId } = await session.send("Browser.getWindowForTarget");
      await session.detach();
      return (await worker(id)).evaluate(async (windowId) => {
        const [tab] = await chrome.tabs.query({ windowId, active: true });
        return { badge: await chrome.action.getBadgeText({ tabId: tab.id }), title: await chrome.action.getTitle({ tabId: tab.id }) };
      }, windowId);
    },
    /** Waits until the button's badge for `page` is `badge`, and returns what it says. */
    async until(page, badge, id = EXTENSION_ID) {
      const deadline = Date.now() + PATIENCE_MS;
      for (;;) {
        const status = await this.status(page, id);
        if (status.badge === badge) return status;
        if (Date.now() > deadline) throw new Error(`the button never showed "${badge}"; it shows "${status.badge}": ${status.title}`);
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    },
    async close() {
      for (const closer of closers.reverse()) {
        try { await closer(); } catch { /* best effort */ }
      }
    },
  };
}

/** What the page's form holds and what its scripts noticed. */
export function formOf(page) {
  return page.evaluate(() => ({
    username: document.getElementById("username")?.value ?? null,
    password: document.getElementById("password")?.value ?? null,
    events: window.seen?.events ?? [],
    submitted: window.seen?.submitted ?? null,
    address: location.href,
  }));
}

/** A copy of the built extension without the `key` that fixes its ID: to the browser, another extension. */
function withoutKey(home) {
  const copy = path.join(home, "forged-extension");
  cpSync(path.resolve(here, "../dist/chromium"), copy, { recursive: true });
  const manifest = JSON.parse(readFileSync(path.join(copy, "manifest.json"), "utf8"));
  delete manifest.key;
  manifest.name = "Not Open Secret Manager";
  writeFileSync(path.join(copy, "manifest.json"), JSON.stringify(manifest));
  return copy;
}
