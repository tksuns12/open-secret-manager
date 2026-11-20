// Tests scripts/publish-extension.mjs against stand-in servers of the two
// stores, which hold what the stores' documentation says the requests are.
//   node --test scripts/publish-extension.test.mjs
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, beforeEach, describe, test } from "node:test";
import { amoToken, credentials, isNewer, main, PublishError, readPackage, REVIEWER_NOTES } from "./publish-extension.mjs";

const SECRETS = {
  OSM_AMO_JWT_ISSUER: "user:1:2",
  OSM_AMO_JWT_SECRET: "amo-secret-never-printed",
  OSM_CWS_PUBLISHER_ID: "publisher-9",
  OSM_CWS_CLIENT_ID: "client-id",
  OSM_CWS_CLIENT_SECRET: "cws-client-secret-never-printed",
  OSM_CWS_REFRESH_TOKEN: "refresh-token-never-printed",
};

function packageFolder({ version = "0.1.1", tamper = false, info = "commit abc\nversion 0.1.1\n" } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "osm-pack-"));
  const files = {
    [`open-secret-manager-firefox-${version}.zip`]: "firefox zip bytes",
    [`open-secret-manager-chromium-${version}.zip`]: "chromium zip bytes",
    [`open-secret-manager-extension-${version}-source.zip`]: "source zip bytes",
  };
  const sums = [];
  for (const [name, text] of Object.entries(files)) {
    writeFileSync(join(dir, name), tamper ? `${text} changed` : text);
    sums.push(`${createHash("sha256").update(text).digest("hex")}  ${name}`);
  }
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

  test("missing credentials are named, never guessed", () => {
    delete process.env.OSM_CWS_REFRESH_TOKEN;
    assert.throws(() => credentials("chromium"), (e) => e instanceof PublishError && /OSM_CWS_REFRESH_TOKEN/.test(e.message));
  });
});

describe("Firefox", () => {
  let amo;
  let base;
  before(async () => {
    let polls = 0;
    amo = stand((req) => {
      const path = req.url;
      if (req.method === "GET" && path === "/api/v5/addons/addon/open-secret-manager/")
        return { json: { status: "public", current_version: { version: "0.1.0" } } };
      if (req.method === "POST" && path === "/api/v5/addons/upload/") return { json: { uuid: "u-1", processed: false } };
      if (req.method === "GET" && path === "/api/v5/addons/upload/u-1/")
        return { json: ++polls < 2 ? { processed: false } : { processed: true, valid: true, validation: { messages: [] } } };
      if (req.method === "POST" && path === "/api/v5/addons/addon/open-secret-manager/versions/")
        return { status: 201, json: { id: 77, version: "0.1.1" } };
      if (req.method === "PATCH" && path === "/api/v5/addons/addon/open-secret-manager/versions/77/") return { json: {} };
      return { status: 404, json: { detail: `unexpected ${req.method} ${path}` } };
    });
    base = await listen(amo.server);
  });
  after(() => amo.server.close());

  test("uploads the add-on as listed, makes the version with its source, and tells the reviewers", async () => {
    process.env.OSM_AMO_BASE = base;
    amo.seen.length = 0;
    await main(["publish", "firefox", "--dir", packageFolder(), "--yes"]);

    const upload = amo.seen.find((r) => r.method === "POST" && r.url === "/api/v5/addons/upload/");
    const sent = upload.body.toString();
    assert.match(sent, /name="upload"; filename="open-secret-manager-firefox-0\.1\.1\.zip"/);
    assert.match(sent, /name="channel"\r\n\r\nlisted/);

    const made = amo.seen.find((r) => r.url.endsWith("/versions/") && r.method === "POST");
    const form = made.body.toString();
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
  });

  test("a version that is not newer than the published one is not sent", async () => {
    process.env.OSM_AMO_BASE = base;
    amo.seen.length = 0;
    await assert.rejects(
      main(["publish", "firefox", "--dir", packageFolder({ version: "0.1.0", info: "commit abc\n" }), "--yes"]),
      /already has 0\.1\.0/,
    );
    assert.equal(amo.seen.filter((r) => r.method === "POST").length, 0);
  });

  test("a dry run uploads nothing", async () => {
    process.env.OSM_AMO_BASE = base;
    amo.seen.length = 0;
    await main(["publish", "firefox", "--dir", packageFolder(), "--dry-run"]);
    assert.equal(amo.seen.filter((r) => r.method !== "GET").length, 0);
    assert.match(output.join("\n"), /nothing was uploaded/);
  });

  test("a package Mozilla finds invalid stops with its messages", async () => {
    const bad = stand((req) => {
      if (req.method === "GET" && req.url === "/api/v5/addons/addon/open-secret-manager/")
        return { json: { status: "public", current_version: { version: "0.1.0" } } };
      if (req.method === "POST" && req.url === "/api/v5/addons/upload/") return { json: { uuid: "u-2", processed: true, valid: false, validation: { messages: [{ type: "error", message: "manifest is wrong" }] } } };
      if (req.url === "/api/v5/addons/upload/u-2/") return { json: { processed: true, valid: false, validation: { messages: [{ type: "error", message: "manifest is wrong" }] } } };
      return { status: 404 };
    });
    process.env.OSM_AMO_BASE = await listen(bad.server);
    await assert.rejects(main(["publish", "firefox", "--dir", packageFolder(), "--yes"]), /manifest is wrong/);
    assert.equal(bad.seen.filter((r) => r.url.endsWith("/versions/")).length, 0);
    bad.server.close();
  });
});

describe("Chrome Web Store", () => {
  let cws;
  let base;
  let statuses;
  before(async () => {
    cws = stand((req) => {
      if (req.url === "/token") return { json: { access_token: "access-token-never-printed" } };
      if (req.method === "POST" && req.url.startsWith("/upload/v2/publishers/publisher-9/items/pnjdoenkfffomcidikbkcegcpgipdjog:upload"))
        return { json: { uploadState: "IN_PROGRESS" } };
      if (req.method === "GET" && req.url.endsWith(":fetchStatus")) return { json: statuses.shift() ?? { lastAsyncUploadState: "SUCCEEDED" } };
      if (req.method === "POST" && req.url.endsWith(":publish")) return { json: { state: "PENDING_REVIEW" } };
      return { status: 404, json: { error: `unexpected ${req.method} ${req.url}` } };
    });
    base = await listen(cws.server);
  });
  after(() => cws.server.close());
  beforeEach(() => {
    statuses = [{ lastAsyncUploadState: "SUCCEEDED" }, { lastAsyncUploadState: "IN_PROGRESS" }, { lastAsyncUploadState: "SUCCEEDED" }];
    process.env.OSM_CWS_BASE = base;
    process.env.OSM_OAUTH_URL = `${base}/token`;
    cws.seen.length = 0;
  });

  test("gets a token from the refresh token, uploads the zip, waits, and submits it for publishing", async () => {
    await main(["publish", "chromium", "--dir", packageFolder(), "--yes"]);
    const token = cws.seen.find((r) => r.url === "/token");
    const form = new URLSearchParams(token.body.toString());
    assert.equal(form.get("grant_type"), "refresh_token");
    assert.equal(form.get("refresh_token"), SECRETS.OSM_CWS_REFRESH_TOKEN);

    const upload = cws.seen.find((r) => r.url.includes(":upload"));
    assert.equal(upload.body.toString(), "chromium zip bytes");
    assert.equal(upload.headers.authorization, "Bearer access-token-never-printed");

    const publish = cws.seen.find((r) => r.url.endsWith(":publish"));
    assert.deepEqual(JSON.parse(publish.body), { publishType: "DEFAULT_PUBLISH" });
  });

  test("--staged holds the approved version for the owner", async () => {
    await main(["publish", "chromium", "--dir", packageFolder(), "--yes", "--staged"]);
    const publish = cws.seen.find((r) => r.url.endsWith(":publish"));
    assert.deepEqual(JSON.parse(publish.body), { publishType: "STAGED_PUBLISH" });
  });

  test("an upload that ends as failed is not submitted", async () => {
    statuses = [{ lastAsyncUploadState: "SUCCEEDED" }, { lastAsyncUploadState: "FAILED" }];
    await assert.rejects(main(["publish", "chromium", "--dir", packageFolder(), "--yes"]), /ended as FAILED/);
    assert.equal(cws.seen.filter((r) => r.url.endsWith(":publish")).length, 0);
  });
});

describe("secrets", () => {
  test("none is ever printed", async () => {
    const amo = stand((req) => {
      if (req.method === "GET") return { json: { status: "public", current_version: { version: "0.1.0" } } };
      return { json: {} };
    });
    process.env.OSM_AMO_BASE = await listen(amo.server);
    await main(["check", "firefox"]);
    await main(["publish", "firefox", "--dir", packageFolder(), "--dry-run"]);
    amo.server.close();
    const printed = output.join("\n");
    for (const secret of Object.values(SECRETS)) assert.ok(!printed.includes(secret), `printed ${secret}`);
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
