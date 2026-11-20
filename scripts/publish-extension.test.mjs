// Tests scripts/publish-extension.mjs against stand-in servers of the two
// stores, which hold what the stores' documentation says the requests are.
// It never reads the owner's keychain (OSM_NO_KEYCHAIN) and sends nothing to
// a real store.
//   node --test scripts/publish-extension.test.mjs
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, beforeEach, describe, test } from "node:test";
import { amoToken, credentials, isNewer, main, PublishError, readPackage, REVIEWER_NOTES } from "./publish-extension.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "publish-extension.mjs");
const SECRETS = {
  OSM_AMO_JWT_ISSUER: "user:1:2",
  OSM_AMO_JWT_SECRET: "amo-secret-never-printed",
  OSM_CWS_PUBLISHER_ID: "publisher-9",
  OSM_CWS_CLIENT_ID: "client-id-never-printed",
  OSM_CWS_CLIENT_SECRET: "cws-client-secret-never-printed",
  OSM_CWS_REFRESH_TOKEN: "refresh-token-never-printed",
};

const scratch = [];
after(() => scratch.forEach((dir) => rmSync(dir, { recursive: true, force: true })));

function temp() {
  const dir = mkdtempSync(join(tmpdir(), "osm-publish-"));
  scratch.push(dir);
  return dir;
}

/** A folder as package-extension.sh makes it, with real zips holding a manifest. */
function packageFolder({ version = "0.1.1", chromiumManifest = version, tamper = false, info = "commit abc\nversion 0.1.1\n" } = {}) {
  const dir = temp();
  const zip = (name, manifestVersion) => {
    const stage = temp();
    writeFileSync(join(stage, "manifest.json"), JSON.stringify({ version: manifestVersion }));
    writeFileSync(join(stage, "payload.txt"), name);
    execFileSync("zip", ["-q", "-X", join(dir, name), "manifest.json", "payload.txt"], { cwd: stage });
  };
  const names = [
    [`open-secret-manager-firefox-${version}.zip`, version],
    [`open-secret-manager-chromium-${version}.zip`, chromiumManifest],
    [`open-secret-manager-extension-${version}-source.zip`, version],
  ];
  const sums = [];
  for (const [name, manifestVersion] of names) {
    zip(name, manifestVersion);
    sums.push(`${createHash("sha256").update(readFileSync(join(dir, name))).digest("hex")}  ${name}`);
  }
  if (tamper) appendFileSync(join(dir, names[0][0]), "changed");
  writeFileSync(join(dir, "SHA256SUMS"), sums.join("\n") + "\n");
  writeFileSync(join(dir, "build-info.txt"), info);
  return dir;
}

/** A server that records each request and answers from `routes`. */
function stand(routes) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const record = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) };
      seen.push(record);
      const route = routes(record, seen);
      res.writeHead(route.status ?? 200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(route.json ?? {}));
    });
  });
  return { server, seen };
}

const listen = (server) => new Promise((done) => server.listen(0, "127.0.0.1", () => done(`http://127.0.0.1:${server.address().port}`)));

let output;
const realLog = console.log;
const realError = console.error;
beforeEach(() => {
  output = [];
  console.log = (...a) => output.push(a.join(" "));
  console.error = (...a) => output.push(a.join(" "));
  for (const key of Object.keys(SECRETS)) process.env[key] = SECRETS[key];
  process.env.OSM_PUBLISH_POLL_MS = "5";
  process.env.OSM_NO_KEYCHAIN = "1";
  delete process.env.OSM_AMO_BASE;
  delete process.env.OSM_CWS_BASE;
  delete process.env.OSM_OAUTH_URL;
});
after(() => {
  console.log = realLog;
  console.error = realError;
});

describe("the pieces", () => {
  test("a Firefox token is HS256 over the issuer, a nonce and at most five minutes", () => {
    const token = amoToken("issuer", "secret", 1_700_000_000);
    const [head, body, signature] = token.split(".");
    assert.deepEqual(JSON.parse(Buffer.from(head, "base64url")), { alg: "HS256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(body, "base64url"));
    assert.equal(claims.iss, "issuer");
    assert.equal(claims.iat, 1_700_000_000);
    assert.ok(claims.exp - claims.iat <= 300);
    assert.ok(claims.jti.length > 8);
    assert.equal(signature, createHmac("sha256", "secret").update(`${head}.${body}`).digest("base64url"));
  });

  test("versions compare as numbers", () => {
    assert.ok(isNewer("0.1.10", "0.1.9"));
    assert.ok(isNewer("0.2", "0.1.9"));
    assert.ok(!isNewer("0.1.1", "0.1.1"));
    assert.ok(!isNewer("0.1.0", "0.1.1"));
  });

  test("a package is read, and one that changed since it was made is refused", () => {
    const pack = readPackage(packageFolder());
    assert.equal(pack.version, "0.1.1");
    assert.deepEqual(Object.keys(pack.files).sort(), ["chromium", "firefox", "source"]);
    assert.throws(() => readPackage(packageFolder({ tamper: true })), /not what SHA256SUMS says/);
    assert.throws(() => readPackage(packageFolder({ info: "with uncommitted changes: not a release\n" })), /not a release/);
  });

  test("a package whose manifest has another version than its name is refused", () => {
    assert.throws(() => readPackage(packageFolder({ chromiumManifest: "0.1.0" })), /holds version 0\.1\.0 in its manifest/);
  });

  test("a folder that is not packaged says so", () => {
    assert.throws(() => readPackage(temp()), /run scripts\/package-extension\.sh first/);
  });

  test("missing credentials are named, never guessed, and the keychain is not asked in a test", () => {
    delete process.env.OSM_CWS_REFRESH_TOKEN;
    assert.throws(() => credentials("chromium"), (e) => e instanceof PublishError && /OSM_CWS_REFRESH_TOKEN/.test(e.message));
  });
});

describe("Firefox", () => {
  let amo;
  let base;
  let notesStatus;
  before(async () => {
    let polls = 0;
    notesStatus = 200;
    amo = stand((req) => {
      const path = req.url;
      if (req.method === "GET" && path === "/api/v5/addons/addon/open-secret-manager/")
        return { json: { status: "public", current_version: { version: "0.1.0" } } };
      if (req.method === "POST" && path === "/api/v5/addons/upload/") return { json: { uuid: "u-1", processed: false } };
      if (req.method === "GET" && path === "/api/v5/addons/upload/u-1/")
        return { json: ++polls % 2 === 1 ? { processed: false } : { processed: true, valid: true, validation: { messages: [] } } };
      if (req.method === "POST" && path === "/api/v5/addons/addon/open-secret-manager/versions/")
        return { status: 201, json: { id: 77, version: "0.1.1" } };
      if (req.method === "PATCH" && path === "/api/v5/addons/addon/open-secret-manager/versions/77/") return { status: notesStatus, json: {} };
      return { status: 404, json: { detail: `unexpected ${req.method} ${path}` } };
    });
    base = await listen(amo.server);
  });
  after(() => amo.server.close());
  beforeEach(() => {
    notesStatus = 200;
    amo.seen.length = 0;
  });

  test("uploads the add-on as listed, makes the version with its source, and tells the reviewers", async () => {
    process.env.OSM_AMO_BASE = base;
    const code = await main(["publish", "firefox", "--dir", packageFolder(), "--yes"]);
    assert.equal(code, 0);

    const upload = amo.seen.find((r) => r.method === "POST" && r.url === "/api/v5/addons/upload/");
    const sent = upload.body.toString("latin1");
    assert.match(sent, /name="upload"; filename="open-secret-manager-firefox-0\.1\.1\.zip"/);
    assert.match(sent, /name="channel"\r\n\r\nlisted/);
    assert.ok(!/content-type: multipart/i.test(JSON.stringify(Object.keys(upload.headers))), "the content type is the form's own");
    assert.match(upload.headers["content-type"], /^multipart\/form-data; boundary=/);

    const made = amo.seen.find((r) => r.url.endsWith("/versions/") && r.method === "POST");
    const form = made.body.toString("latin1");
    assert.match(form, /name="upload"\r\n\r\nu-1/);
    assert.match(form, /name="source"; filename="open-secret-manager-extension-0\.1\.1-source\.zip"/);

    const notes = amo.seen.find((r) => r.method === "PATCH");
    assert.equal(JSON.parse(notes.body).approval_notes, REVIEWER_NOTES);

    // Every request carries a token signed with the secret.
    for (const r of amo.seen) {
      const [, token] = r.headers.authorization.split(" ");
      const [head, body, signature] = token.split(".");
      assert.equal(signature, createHmac("sha256", SECRETS.OSM_AMO_JWT_SECRET).update(`${head}.${body}`).digest("base64url"));
    }
    assert.ok(output.join("\n").includes("made version 0.1.1"));
    assert.ok(amo.seen.filter((r) => r.url === "/api/v5/addons/upload/u-1/").length >= 2, "it waited for the check");
  });

  test("notes that could not be saved are said, and the run does not end as a success", async () => {
    process.env.OSM_AMO_BASE = base;
    notesStatus = 500;
    const code = await main(["publish", "firefox", "--dir", packageFolder(), "--yes"]);
    assert.equal(code, 2);
    assert.match(output.join("\n"), /the notes for the reviewers were not saved/);
  });

  test("a version that is not newer than the published one is not sent", async () => {
    process.env.OSM_AMO_BASE = base;
    const dir = packageFolder({ version: "0.1.0", info: "commit abc\n" });
    await assert.rejects(main(["publish", "firefox", "--dir", dir, "--yes"]), /already has 0\.1\.0/);
    assert.equal(amo.seen.filter((r) => r.method === "POST").length, 0);
  });

  test("a dry run uploads nothing", async () => {
    process.env.OSM_AMO_BASE = base;
    await main(["publish", "firefox", "--dir", packageFolder(), "--dry-run"]);
    assert.equal(amo.seen.filter((r) => r.method !== "GET").length, 0);
    assert.match(output.join("\n"), /nothing was uploaded/);
  });

  test("an endpoint that is not the store's is said, since the keys go there", async () => {
    process.env.OSM_AMO_BASE = base;
    await main(["publish", "firefox", "--dir", packageFolder(), "--dry-run"]);
    assert.match(output.join("\n"), /NOTE: OSM_AMO_BASE is set/);
  });

  test("a package Mozilla finds invalid stops with its messages", async () => {
    const message = { type: "error", message: "manifest is wrong" };
    const bad = stand((req) => {
      if (req.method === "GET" && req.url === "/api/v5/addons/addon/open-secret-manager/")
        return { json: { status: "public", current_version: { version: "0.1.0" } } };
      if (req.method === "POST" && req.url === "/api/v5/addons/upload/") return { json: { uuid: "u-2" } };
      if (req.url === "/api/v5/addons/upload/u-2/") return { json: { processed: true, valid: false, validation: { messages: [message] } } };
      return { status: 404 };
    });
    process.env.OSM_AMO_BASE = await listen(bad.server);
    try {
      await assert.rejects(main(["publish", "firefox", "--dir", packageFolder(), "--yes"]), /manifest is wrong/);
      assert.equal(bad.seen.filter((r) => r.url.endsWith("/versions/")).length, 0);
    } finally {
      bad.server.close();
    }
  });
});

describe("Chrome Web Store", () => {
  let cws;
  let base;
  let statuses;
  let uploadState;
  let uploadStatus;
  before(async () => {
    cws = stand((req) => {
      if (req.url === "/token") return { json: { access_token: "access-token-never-printed" } };
      if (req.method === "POST" && req.url.startsWith("/upload/v2/publishers/publisher-9/items/pnjdoenkfffomcidikbkcegcpgipdjog:upload"))
        return { status: uploadStatus, json: { uploadState } };
      if (req.method === "GET" && req.url.endsWith(":fetchStatus")) return { json: statuses.shift() ?? { lastAsyncUploadState: "SUCCEEDED" } };
      if (req.method === "POST" && req.url.endsWith(":publish")) return { json: { state: "PENDING_REVIEW" } };
      return { status: 404, json: { error: `unexpected ${req.method} ${req.url}` } };
    });
    base = await listen(cws.server);
  });
  after(() => cws.server.close());
  beforeEach(() => {
    // The first answer is the check before the question; the rest are the waiting.
    statuses = [{}, { lastAsyncUploadState: "IN_PROGRESS" }, { lastAsyncUploadState: "SUCCEEDED" }, { lastAsyncUploadState: "SUCCEEDED" }];
    uploadState = "IN_PROGRESS";
    uploadStatus = 200;
    process.env.OSM_CWS_BASE = base;
    process.env.OSM_OAUTH_URL = `${base}/token`;
    cws.seen.length = 0;
  });
  const polls = () => cws.seen.filter((r) => r.url.endsWith(":fetchStatus")).length;

  test("gets a token from the refresh token, uploads the zip, waits, and submits it for publishing", async () => {
    await main(["publish", "chromium", "--dir", packageFolder(), "--yes"]);
    const token = cws.seen.find((r) => r.url === "/token");
    const form = new URLSearchParams(token.body.toString());
    assert.equal(form.get("grant_type"), "refresh_token");
    assert.equal(form.get("refresh_token"), SECRETS.OSM_CWS_REFRESH_TOKEN);

    const upload = cws.seen.find((r) => r.url.includes(":upload"));
    assert.equal(upload.headers.authorization, "Bearer access-token-never-printed");
    assert.equal(upload.body.subarray(0, 2).toString(), "PK", "the body is the zip");

    const order = cws.seen.map((r) => r.url.split(":").pop().split("?")[0]);
    const publishAt = order.lastIndexOf("publish");
    assert.ok(publishAt > order.lastIndexOf("fetchStatus"), "it submitted after the last wait");
    assert.equal(polls(), 4, "the check, an unfinished upload, then two settled answers");
    assert.deepEqual(JSON.parse(cws.seen[publishAt].body), { publishType: "DEFAULT_PUBLISH" });
  });

  test("an upload the store says succeeded needs no waiting", async () => {
    uploadState = "SUCCEEDED";
    await main(["publish", "chromium", "--dir", packageFolder(), "--yes"]);
    assert.equal(polls(), 1, "only the check before the question");
    assert.ok(cws.seen.some((r) => r.url.endsWith(":publish")));
  });

  test("an upload the store says failed is not submitted", async () => {
    uploadState = "FAILED";
    await assert.rejects(main(["publish", "chromium", "--dir", packageFolder(), "--yes"]), /refused the upload/);
    assert.equal(cws.seen.filter((r) => r.url.endsWith(":publish")).length, 0);
  });

  test("--staged holds the approved version for the owner", async () => {
    await main(["publish", "chromium", "--dir", packageFolder(), "--yes", "--staged"]);
    const publish = cws.seen.find((r) => r.url.endsWith(":publish"));
    assert.deepEqual(JSON.parse(publish.body), { publishType: "STAGED_PUBLISH" });
  });

  test("an upload that ends as failed while waiting is not submitted, and the run says where it stands", async () => {
    statuses = [{}, { lastAsyncUploadState: "FAILED" }];
    await assert.rejects(
      main(["publish", "chromium", "--dir", packageFolder(), "--yes"]),
      /ended as FAILED[\s\S]*uploaded but not submitted/,
    );
    assert.equal(cws.seen.filter((r) => r.url.endsWith(":publish")).length, 0);
  });

  test("a store error does not print the publisher's ID", async () => {
    uploadStatus = 403;
    let message = "";
    await main(["publish", "chromium", "--dir", packageFolder(), "--yes"]).catch((error) => {
      message = error.message;
    });
    assert.match(message, /answered 403/);
    assert.ok(!message.includes("publisher-9"), message);
  });
});

describe("both stores", () => {
  test("when the second store fails, the first is said to be sent already", async () => {
    const amo = stand((req) => {
      if (req.method === "GET" && req.url === "/api/v5/addons/addon/open-secret-manager/") return { json: { status: "public", current_version: { version: "0.1.0" } } };
      if (req.method === "POST" && req.url === "/api/v5/addons/upload/") return { json: { uuid: "u-1", processed: true, valid: true } };
      if (req.url === "/api/v5/addons/upload/u-1/") return { json: { processed: true, valid: true } };
      if (req.method === "POST" && req.url.endsWith("/versions/")) return { status: 201, json: { id: 5, version: "0.1.1" } };
      return { json: {} };
    });
    const cws = stand((req) => (req.url === "/token" ? { json: { access_token: "t" } } : req.method === "GET" ? { json: {} } : { status: 500, json: { error: "down" } }));
    process.env.OSM_AMO_BASE = await listen(amo.server);
    process.env.OSM_CWS_BASE = await listen(cws.server);
    process.env.OSM_OAUTH_URL = `${process.env.OSM_CWS_BASE}/token`;
    try {
      await assert.rejects(
        main(["publish", "all", "--dir", packageFolder(), "--yes"]),
        /Already sent and in review: firefox\. Do not send firefox again[\s\S]*Still to send: chromium/,
      );
    } finally {
      amo.server.close();
      cws.server.close();
    }
  });
});

describe("secrets", () => {
  test("none is ever printed, in either store, on success or on a store's error", async () => {
    const amo = stand((req) => ({ json: { status: "public", current_version: { version: "0.1.0" } } }));
    const cws = stand((req) => (req.url === "/token" ? { json: { access_token: "access-token-never-printed" } } : { json: { publishedItemRevisionStatus: { state: "PUBLISHED" } } }));
    process.env.OSM_AMO_BASE = await listen(amo.server);
    process.env.OSM_CWS_BASE = await listen(cws.server);
    process.env.OSM_OAUTH_URL = `${process.env.OSM_CWS_BASE}/token`;
    await main(["check", "all"]);
    await main(["publish", "all", "--dir", packageFolder(), "--dry-run"]);
    amo.server.close();
    cws.server.close();
    const printed = output.join("\n");
    for (const secret of [...Object.values(SECRETS), "access-token-never-printed"]) assert.ok(!printed.includes(secret), `printed ${secret}`);
  });

  test("with no terminal and no --yes, nothing is sent", async () => {
    const amo = stand(() => ({ json: { status: "public", current_version: { version: "0.1.0" } } }));
    process.env.OSM_AMO_BASE = await listen(amo.server);
    const tty = process.stdin.isTTY;
    process.stdin.isTTY = false;
    try {
      await assert.rejects(main(["publish", "firefox", "--dir", packageFolder()]), /no terminal to ask on/);
    } finally {
      process.stdin.isTTY = tty;
      amo.server.close();
    }
    assert.equal(amo.seen.filter((r) => r.method === "POST").length, 0);
  });
});

describe("the command line", () => {
  const run = (args, { cwd = tmpdir(), script = SCRIPT } = {}) =>
    spawnSync(process.execPath, [script, ...args], {
      cwd,
      encoding: "utf8",
      env: { ...process.env, OSM_NO_KEYCHAIN: "1", OSM_AMO_JWT_ISSUER: "", OSM_AMO_JWT_SECRET: "" },
    });

  test("it runs from any folder, and says what is missing instead of a stack", () => {
    const result = run(["publish", "firefox", "--dry-run", "--dir", packageFolder()]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /No Firefox credentials/);
    const unpackaged = run(["publish", "firefox", "--dry-run"]);
    assert.match(unpackaged.stderr, /run scripts\/package-extension\.sh first/);
    assert.ok(!/fatal: not a git repository/.test(unpackaged.stderr), unpackaged.stderr);
    assert.ok(!/node:internal|at .*\.mjs/.test(result.stderr), result.stderr);
  });

  test("it runs through a link to the repository, and is not silent", () => {
    const link = join(temp(), "repo-link");
    symlinkSync(join(dirname(SCRIPT), ".."), link);
    const result = run([], { script: join(link, "scripts", "publish-extension.mjs") });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Usage/);
  });

  test("a word too many, an unknown option, and a --dir without a folder are refused", () => {
    assert.match(run(["publish", "firefox", "chromium"]).stderr, /Too many words/);
    assert.match(run(["publish", "--nope"]).stderr, /Unknown option/);
    assert.match(run(["publish", "--dir"]).stderr, /--dir needs a folder/);
  });
});
