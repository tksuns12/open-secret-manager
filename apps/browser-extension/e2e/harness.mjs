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
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "../../..");
const built = (name) => path.join(repository, "target/debug", name);

/** Which browser the tests run in: `OSM_BROWSER=firefox` for Firefox, Chromium otherwise. */
export const BROWSER = process.env.OSM_BROWSER === "firefox" ? "firefox" : "chromium";

const HOST_NAME = "org.opensecretmanager.native";
const CHROMIUM_EXTENSION_ID = "hjgekjgkjnakgmiopldddikdkcjhnmge";
const FIREFOX_EXTENSION_ID = "extension@opensecretmanager.org";
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

/** A card form's fields, with the ids the tests read them by. */
const cardFields = {
  holder: `<input id="cc-name" autocomplete="cc-name" placeholder="Name on card">`,
  number: `<input id="cc-number" autocomplete="cc-number" inputmode="numeric" placeholder="Card number">`,
  split: [1, 2, 3, 4].map((part) => `<input id="cc-number-${part}" autocomplete="cc-number" maxlength="4" inputmode="numeric" size="4">`).join(""),
  month: `<select id="cc-month" autocomplete="cc-exp-month"><option value="">MM</option>${Array.from({ length: 12 }, (_, index) => `<option>${String(index + 1).padStart(2, "0")}</option>`).join("")}</select>`,
  year: `<select id="cc-year" autocomplete="cc-exp-year"><option value="">YYYY</option>${[2026, 2027, 2028, 2029, 2030, 2031].map((year) => `<option>${year}</option>`).join("")}</select>`,
  code: `<input id="cc-code" autocomplete="cc-csc" inputmode="numeric" placeholder="CVC">`,
  // A second code field drawn with no size, which the owner cannot see.
  hidden: `<input id="cc-hidden" autocomplete="cc-csc" style="width:0;height:0;padding:0;border:0;margin:0">`,
};
const cardPage = (title, body) => `<!doctype html><meta charset="utf-8"><title>${title}</title><form id="pay">${body}</form>`;

function respond(request, response) {
  const url = new URL(request.url, "https://placeholder.test");
  const send = (body, headers = {}) => { response.writeHead(200, { "content-type": "text/html; charset=utf-8", ...headers }); response.end(body); };
  switch (url.pathname) {
    case "/login": return send(loginForm("Sign in"));
    case "/next": return send(loginForm("Another page of the same site"));
    // A page that keeps scripts that came later from hearing that it is being left.
    case "/sticky": return send(loginForm("A page that hides its leaving") + `<script>window.addEventListener("pagehide", (event) => event.stopImmediatePropagation(), true);</script>`);
    // A page its site serves sandboxed: the site's address, but an origin of its own.
    case "/sandboxed": return send(loginForm("Sandboxed"), { "content-security-policy": "sandbox allow-scripts allow-forms" });
    case "/empty": return send(`<!doctype html><title>Nothing to fill</title><p>No form here.</p>`);
    // A page with no form of its own that shows another site's form in a frame.
    case "/framing": return send(`<!doctype html><title>Framing page</title><p>The form below belongs to another site.</p><iframe id="inner" src="https://login.test/login" width="400" height="200"></iframe>`);
    // A page with its own form and another site's form in a frame.
    case "/both": return send(loginForm("Outer form") + `<iframe id="inner" src="https://login.test/login" width="400" height="200"></iframe>`);
    // A form that asks for the user name only.
    case "/name-first": return send(`<!doctype html><title>Name first</title><form id="login"><input id="username" name="email" type="email" autocomplete="username"><button type="submit">Next</button></form><script>window.seen = { submitted: false }; document.getElementById("login").addEventListener("submit", () => { window.seen.submitted = true; });</script>`);
    case "/submitted": return send(`<!doctype html><title>Submitted</title>`);
    // A checkout page with its card form in the page itself.
    case "/checkout": return send(cardPage("Checkout", Object.entries(cardFields).filter(([name]) => name !== "split").map(([, field]) => field).join("")));
    // One whose number and code are in a frame of its own origin.
    case "/checkout-framed": return send(cardPage("Checkout, framed", cardFields.holder + cardFields.month + cardFields.year) + `<iframe id="card-frame" src="/card-frame" width="400" height="120"></iframe>`);
    case "/card-frame": return send(cardPage("Card frame", cardFields.split + cardFields.code));
    // One whose number and code are in a frame of a payment provider, another site.
    case "/checkout-elsewhere": return send(cardPage("Checkout, elsewhere", cardFields.holder + cardFields.month + cardFields.year) + `<iframe id="card-frame" src="https://other.test/card-frame" width="400" height="120"></iframe>`);
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
export async function start(options = {}) {
  const closers = [];
  try {
    return await prepare(closers, options);
  } catch (error) {
    // Leave nothing running or lying about when setting up fails.
    for (const closer of closers.reverse()) {
      try { await closer(); } catch { /* best effort */ }
    }
    throw error;
  }
}

async function prepare(closers, { logins = [], cards = [], fakeHost = false, standIn = ["ask"], registerHost = true, forged = false, appHome = null, hostProgram = null }) {
  // Short, because a socket's path has to fit in about a hundred bytes.
  const home = mkdtempSync("/tmp/osm");
  closers.push(() => {
    // Firefox makes the folders a home folder has, which macOS protects
    // from deletion until the protection is taken off.
    if (process.platform === "darwin") execFileSync("chmod", ["-RN", home], { stdio: "ignore" });
    rmSync(home, { recursive: true, force: true });
  });
  // With `appHome`, the desktop app itself is running for that home folder:
  // the browser and the host use it, and nothing stands in for the app.
  if (appHome) return browse({ home, accountHome: appHome, closers, fakeHost, hostProgram, registerHost, forged, app: null, items: {}, vault: null });
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
  // Cards: [title, cardholder, number, month, year, code].
  for (const [title, ...card] of cards) {
    items[title] = fill("add-card", vault, title, ...card).split(" ")[1];
  }
  let app = null;
  if (standIn) {
    const child = spawn(built("osm-fill"), ["serve", vault, "-", ...standIn], { env, stdio: ["pipe", "pipe", "inherit"] });
    closers.push(() => child.kill());
    app = new Lines(child);
    await app.expect("LISTENING");
  }
  return browse({ home, accountHome: home, closers, fakeHost, hostProgram, registerHost, forged, app, items, vault });
}

/**
 * Where the browser can start `program` from. On macOS a browser does not
 * start a program kept on an external disk, which the repository may be on:
 * the program is left hanging before it runs. So it is started from a copy
 * in the account's caches folder, one per build of it, kept between runs so
 * that macOS checks each build only once; older builds' copies are removed.
 */
function startable(program) {
  if (process.platform !== "darwin") return program;
  const name = path.basename(program);
  const folder = path.join(os.homedir(), "Library/Caches/OpenSecretManager-tests", name);
  const build = createHash("sha256").update(readFileSync(program)).digest("hex").slice(0, 16);
  const copy = path.join(folder, build, name);
  if (!existsSync(copy)) {
    mkdirSync(path.dirname(copy), { recursive: true });
    cpSync(program, `${copy}.partial`);
    chmodSync(`${copy}.partial`, 0o755);
    renameSync(`${copy}.partial`, copy);
  }
  for (const other of readdirSync(folder)) {
    if (other !== build) rmSync(path.join(folder, other), { recursive: true, force: true });
  }
  return copy;
}

/** The pages, and a browser with the extension, for the account whose home folder is `accountHome`. */
async function browse({ home, accountHome, closers, fakeHost, hostProgram, registerHost, forged, app, items, vault }) {
  // The pages: one server for https under every name, one for plain http.
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=login.test",
    "-addext", "subjectAltName=DNS:login.test,DNS:*.login.test,DNS:framing.test,DNS:other.test",
    "-keyout", path.join(home, "key.pem"), "-out", path.join(home, "cert.pem")], { stdio: "ignore" });
  const secure = https.createServer({ key: readFileSync(path.join(home, "key.pem")), cert: readFileSync(path.join(home, "cert.pem")) }, respond);
  const plain = http.createServer(respond);
  const [securePort, plainPort] = [await listen(secure), await listen(plain)];
  closers.push(() => secure.close(), () => plain.close());

  // The real host, or a program that answers wrongly on purpose in its
  // place. That one is started as the file it is, not through a script
  // written for each run: macOS holds the first start of a file it has not
  // seen until it has checked it, which can take many seconds.
  // `hostProgram` names the real host somewhere else: inside a packaged app.
  const host = hostProgram ?? startable(fakeHost ? path.join(here, "fake-host.mjs") : built("osm-native-host"));
  const setup = { home, accountHome, closers, host, registerHost, forged, securePort, plainPort };
  const driver = BROWSER === "firefox" ? await firefoxWith(setup) : await chromiumWith(setup);
  let pressed = null;

  return {
    home, app, items, vault,
    /** What the app calls the kind of browser a request came from. */
    kind: driver.kind,
    /** Tells the fake host how to answer the next request. */
    plan(mode) {
      rmSync(path.join(home, "fake-host-go"), { force: true });
      writeFileSync(path.join(home, "fake-host-plan.json"), JSON.stringify({ mode }));
    },
    /** Lets a fake host that was told to answer `late` send its reply now. */
    letHostAnswer() { writeFileSync(path.join(home, "fake-host-go"), ""); },
    /** What the fake host was sent, one message per entry, and `closed` when the browser let it go. */
    hostLog() {
      const file = path.join(home, "fake-host.log");
      return existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean) : [];
    },
    /** Opens `address` in a new tab. */
    open: driver.open,
    /** Presses the extension's toolbar button for the tab showing `page`, as the owner would. With `forged`, the button of the other extension. */
    press(page, options) {
      pressed = page;
      return driver.press(page, options);
    },
    /** What the button says for the page pressed last, for a test to say how far a request got. */
    pressedStatus: async () => (pressed ? driver.status(pressed) : null),
    /** What the toolbar button says for the tab showing `page`: `{ badge, title }`. */
    status: driver.status,
    /**
     * Waits until the button's badge for `page` is `badge` and, with
     * `says`, its title matches that; returns what it says. The two are
     * set one after the other, so they are waited for together.
     */
    async until(page, badge, { forged = false, says = null } = {}) {
      const deadline = Date.now() + PATIENCE_MS;
      for (;;) {
        const status = await driver.status(page, { forged });
        if (status.badge === badge && (!says || says.test(status.title))) return status;
        if (Date.now() > deadline) throw new Error(`the button never showed "${badge}"${says ? ` saying ${says}` : ""}; it shows "${status.badge}": ${status.title}`);
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

/** Run in a page: what its form holds and what its scripts noticed. */
const FORM = `({
  username: document.getElementById("username")?.value ?? null,
  password: document.getElementById("password")?.value ?? null,
  events: window.seen?.events ?? [],
  submitted: window.seen?.submitted ?? null,
  address: location.href,
})`;

/** Run in a frame: what its form holds, once it is the login page. */
/** What a checkout page's card form holds, the page's own fields and those of a frame of its origin. */
const CARD = `(() => {
  const frame = document.getElementById("card-frame");
  const inFrame = (() => { try { return frame?.contentDocument ?? null; } catch { return null; } })();
  const value = (id) => (document.getElementById(id) ?? inFrame?.getElementById(id))?.value ?? null;
  const split = [1, 2, 3, 4].map((part) => value("cc-number-" + part));
  return { holder: value("cc-name"), number: value("cc-number") ?? (split.every((part) => part !== null) ? split.join("") : null),
    month: value("cc-month"), year: value("cc-year"), code: value("cc-code"), hidden: value("cc-hidden") };
})()`;
const INNER = `(location.href === "https://login.test/login" && document.getElementById("password")) ? [document.getElementById("username").value, document.getElementById("password").value] : null`;

async function eventually(what, attempt) {
  const deadline = Date.now() + PATIENCE_MS;
  for (;;) {
    const found = await attempt();
    if (found) return found;
    if (Date.now() > deadline) throw new Error(`never happened: ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

/** A copy of a built extension that the browser takes for another one. */
function forgedCopy(home, browser, change) {
  const copy = path.join(home, "forged-extension");
  cpSync(path.resolve(here, "../dist", browser), copy, { recursive: true });
  const manifest = JSON.parse(readFileSync(path.join(copy, "manifest.json"), "utf8"));
  manifest.name = "Not Open Secret Manager";
  change(manifest);
  writeFileSync(path.join(copy, "manifest.json"), JSON.stringify(manifest));
  return copy;
}

/**
 * Headless Chromium (Playwright's Chrome for Testing) with the extension.
 * The toolbar button is pressed through the browser's debugging interface,
 * which grants the tab what a real press grants.
 */
async function chromiumWith({ home, accountHome, closers, host, registerHost, forged, securePort, plainPort }) {
  const { chromium } = await import("playwright");
  const env = { ...process.env, HOME: accountHome };
  delete env.XDG_DATA_HOME;
  // The browser's own folder, with the host registered in it as the app's
  // Browser panel would register it in a real browser's folder.
  const profile = path.join(home, "profile");
  if (registerHost) {
    mkdirSync(path.join(profile, "NativeMessagingHosts"), { recursive: true });
    writeFileSync(path.join(profile, "NativeMessagingHosts", `${HOST_NAME}.json`), JSON.stringify({
      name: HOST_NAME,
      description: "Open Secret Manager native messaging host",
      path: host,
      type: "stdio",
      allowed_origins: [`chrome-extension://${CHROMIUM_EXTENSION_ID}/`],
    }));
  }
  const extension = path.resolve(here, "../dist/chromium");
  // Without the `key` that fixes its ID, the same code is another extension.
  const extensions = [extension, ...(forged ? [forgedCopy(home, "chromium", (manifest) => { delete manifest.key; })] : [])].join(",");
  const context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    env,
    ignoreHTTPSErrors: true,
    args: [
      `--disable-extensions-except=${extensions}`,
      `--load-extension=${extensions}`,
      // Lets the tests press the extension's toolbar button.
      "--enable-unsafe-extension-debugging",
      // Every `.test` name is this machine: plain.test over http, the rest
      // over https, whatever port the address names.
      `--host-resolver-rules=MAP plain.test 127.0.0.1:${plainPort}, MAP *.test 127.0.0.1:${securePort}`,
    ],
  });
  closers.push(() => context.close());

  const worker = (id) => eventually(`the extension ${id} starts`, () => context.serviceWorkers().find((candidate) => candidate.url().startsWith(`chrome-extension://${id}/`)));
  // A press that comes before the extension has finished starting, right
  // after it was put into a new browser, is lost. Wait until it listens.
  const listening = (id) => eventually(`the extension ${id} listens for its button`, async () => (await worker(id)).evaluate(() => chrome.action.onClicked.hasListeners()));
  await listening(CHROMIUM_EXTENSION_ID);
  let forgedId = null;
  if (forged) {
    // The other extension is whichever is not ours.
    forgedId = await eventually("the other extension starts", () => context.serviceWorkers().map((candidate) => new URL(candidate.url()).host).find((id) => id !== CHROMIUM_EXTENSION_ID));
    await listening(forgedId);
  }
  const idOf = (which) => (which?.forged ? forgedId : CHROMIUM_EXTENSION_ID);

  return {
    kind: "Chromium",
    async open(address) {
      const page = await context.newPage();
      await page.goto(address);
      return {
        raw: page,
        goto: (next) => page.goto(next),
        back: () => page.goBack(),
        reload: () => page.reload(),
        close: () => page.close(),
        isClosed: () => page.isClosed(),
        form: () => page.evaluate(FORM),
        card: () => page.evaluate(CARD),
        innerForm: () => eventually("the frame shows the login page", async () => {
          const frame = page.frames().find((candidate) => candidate !== page.mainFrame());
          return frame ? frame.evaluate(INNER).catch(() => null) : null;
        }),
      };
    },
    async press({ raw: page }, which) {
      await page.bringToFront();
      // The press is addressed to the tab, which the browser knows under
      // another name than the page inside it; the tab is found by its
      // address, so tests give each tab its own.
      const session = await context.browser().newBrowserCDPSession();
      const { targetInfos } = await session.send("Target.getTargets", { filter: [{ type: "tab" }] });
      const tabs = targetInfos.filter((tab) => tab.url === page.url());
      if (tabs.length !== 1) throw new Error(`${tabs.length} tabs show ${page.url()}`);
      await session.send("Extensions.triggerAction", { id: idOf(which), targetId: tabs[0].targetId });
      await session.detach();
    },
    async status({ raw: page }, which) {
      // The extension is not told tabs' addresses, so the tab is found as
      // the one in front in the page's window.
      await page.bringToFront();
      const session = await context.newCDPSession(page);
      const { windowId } = await session.send("Browser.getWindowForTarget");
      await session.detach();
      return (await worker(idOf(which))).evaluate(async (windowId) => {
        const [tab] = await chrome.tabs.query({ windowId, active: true });
        return { badge: await chrome.action.getBadgeText({ tabId: tab.id }), title: await chrome.action.getTitle({ tabId: tab.id }) };
      }, windowId);
    },
  };
}

/** Sends every `.test` name to this machine: https to one server, http to the other. Anything else is refused. */
async function proxyTo(securePort, plainPort) {
  const proxy = http.createServer((request, response) => {
    const target = new URL(request.url);
    if (!target.hostname.endsWith(".test")) { response.destroy(); return; }
    const forward = http.request({ host: "127.0.0.1", port: plainPort, path: target.pathname + target.search, method: request.method, headers: request.headers }, (answer) => {
      response.writeHead(answer.statusCode, answer.headers);
      answer.pipe(response);
    });
    forward.on("error", () => response.destroy());
    request.pipe(forward);
  });
  proxy.on("connect", (request, socket, head) => {
    const name = request.url.split(":")[0];
    // plain.test has no https side, so that it stays an http page.
    if (!name.endsWith(".test") || name === "plain.test") { socket.destroy(); return; }
    const upstream = net.connect(securePort, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
  });
  const sockets = new Set();
  proxy.on("connection", (socket) => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });
  const port = await listen(proxy);
  return { port, close() { for (const socket of sockets) socket.destroy(); proxy.close(); } };
}

/**
 * Headless Firefox with the extension installed as a temporary add-on.
 * The toolbar button is clicked in the browser's own interface.
 */
async function firefoxWith({ home, accountHome, closers, host, registerHost, forged, securePort, plainPort }) {
  const { Builder, By } = await import("selenium-webdriver");
  const firefox = (await import("selenium-webdriver/firefox.js")).default;
  // Firefox looks for the host's manifest under the account's home folder,
  // which it takes from the system unless this variable says otherwise.
  const env = { ...process.env, HOME: accountHome, CFFIXED_USER_HOME: accountHome };
  delete env.XDG_DATA_HOME;
  // Firefox has one place per account for it, so for the real app's
  // account nothing is written here: connect Firefox in the app's Browser
  // panel first.
  if (registerHost && accountHome === home) {
    const folder = process.platform === "darwin" ? path.join(accountHome, "Library/Application Support/Mozilla/NativeMessagingHosts") : path.join(accountHome, ".mozilla/native-messaging-hosts");
    mkdirSync(folder, { recursive: true });
    writeFileSync(path.join(folder, `${HOST_NAME}.json`), JSON.stringify({
      name: HOST_NAME,
      description: "Open Secret Manager native messaging host",
      path: host,
      type: "stdio",
      allowed_extensions: [FIREFOX_EXTENSION_ID],
    }));
  }
  const proxy = await proxyTo(securePort, plainPort);
  closers.push(() => proxy.close());

  const options = new firefox.Options()
    .setBinary(process.env.OSM_FIREFOX ?? "/Applications/Firefox.app/Contents/MacOS/firefox")
    .addArguments("-headless")
    .setAcceptInsecureCerts(true)
    .setPreference("network.proxy.type", 1)
    .setPreference("network.proxy.http", "127.0.0.1")
    .setPreference("network.proxy.http_port", proxy.port)
    .setPreference("network.proxy.ssl", "127.0.0.1")
    .setPreference("network.proxy.ssl_port", proxy.port)
    .setPreference("network.proxy.no_proxies_on", "")
    .setPreference("network.proxy.allow_hijacking_localhost", true)
    // An http address stays http.
    .setPreference("dom.security.https_first", false)
    .setPreference("dom.security.https_only_mode", false);
  // The argument lets the tests reach the browser's own interface, where
  // the toolbar button is.
  const service = new firefox.ServiceBuilder().setEnvironment(env).addArguments("--allow-system-access");
  const driver = await new Builder().forBrowser("firefox").setFirefoxOptions(options).setFirefoxService(service).build();
  closers.push(() => driver.quit());

  await driver.installAddon(path.resolve(here, "../dist/firefox"), true);
  const forgedId = "another@example.org";
  if (forged) await driver.installAddon(forgedCopy(home, "firefox", (manifest) => { manifest.browser_specific_settings.gecko.id = forgedId; }), true);
  /** The button itself inside an extension's toolbar item. */
  const ACTION = ".unified-extensions-item-action-button";
  /** The toolbar item of an extension, as Firefox names it. */
  const button = (which) => `${(which?.forged ? forgedId : FIREFOX_EXTENSION_ID).toLowerCase().replace(/[^a-z0-9_-]/g, "_")}-browser-action`;
  /** Runs `action` in the browser's own interface rather than in the page. */
  const inChrome = async (action) => {
    await driver.setContext(firefox.Context.CHROME);
    try { return await action(); } finally { await driver.setContext(firefox.Context.CONTENT); }
  };
  await eventually("the extension's button is in the toolbar", () => inChrome(() => driver.executeScript("return document.getElementById(arguments[0]) !== null;", button())));
  const first = await driver.getWindowHandle();

  return {
    kind: "Firefox",
    async open(address) {
      await driver.switchTo().newWindow("tab");
      const handle = await driver.getWindowHandle();
      await driver.get(address);
      let closed = false;
      const here = () => driver.switchTo().window(handle);
      return {
        handle,
        async goto(next) { await here(); await driver.get(next); },
        async back() { await here(); await driver.navigate().back(); },
        async reload() { await here(); await driver.navigate().refresh(); },
        async close() { await here(); await driver.close(); closed = true; await driver.switchTo().window(first); },
        isClosed: () => closed,
        async form() { await here(); return driver.executeScript(`return ${FORM};`); },
        async card() { await here(); return driver.executeScript(`return ${CARD};`); },
        innerForm: () => eventually("the frame shows the login page", async () => {
          await here();
          await driver.switchTo().frame(await driver.findElement(By.id("inner")));
          try { return await driver.executeScript(`return ${INNER};`); } finally { await driver.switchTo().defaultContent(); }
        }),
      };
    },
    async press({ handle }, which) {
      await driver.switchTo().window(handle);
      await inChrome(async () => { await driver.findElement(By.css(`#${button(which)} ${ACTION}`)).click(); });
    },
    async status({ handle }, which) {
      await driver.switchTo().window(handle);
      return inChrome(() => driver.executeScript(
        "const node = document.querySelector(arguments[0]); return { badge: node.getAttribute('badge') || '', title: node.getAttribute('tooltiptext') || '' };",
        `#${button(which)} ${ACTION}`,
      ));
    },
  };
}
