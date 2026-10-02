#!/usr/bin/env node
// Stands in for the native messaging host in tests of the extension alone,
// and answers a fill request wrongly on purpose. How it answers is read
// from `fake-host-plan.json` in the home folder; what it is sent is written
// to `fake-host.log` there.
import { appendFileSync, readFileSync } from "node:fs";
import path from "node:path";

const home = process.env.HOME;
const log = (line) => appendFileSync(path.join(home, "fake-host.log"), line + "\n");

function frame(body) {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(body.length);
  return Buffer.concat([prefix, body]);
}
const send = (message) => process.stdout.write(frame(Buffer.from(JSON.stringify(message))));
const later = (ms, action) => setTimeout(action, ms);

function answer(request) {
  const { mode } = JSON.parse(readFileSync(path.join(home, "fake-host-plan.json"), "utf8"));
  const { requestId, tabId, frameId, documentId, origin } = request;
  const good = { type: "fill_reply", requestId, tabId, frameId, documentId, origin, username: "fake-user", password: "fake-password" };
  const deny = () => later(500, () => send({ type: "error", requestId, code: "denied" }));
  send({ type: "waiting", requestId });
  switch (mode) {
    case "good": return send(good);
    // The right reply, after a while.
    case "late": return later(5000, () => send(good));
    // The same reply a second time, and once more after a moment.
    case "twice": send(good); send(good); return later(300, () => send(good));
    // A reply that names the request but not what it was for.
    case "other-tab": return send({ ...good, tabId: tabId + 1 });
    case "other-frame": return send({ ...good, frameId: 1 });
    case "other-document": return send({ ...good, documentId: "another-document" });
    case "other-origin": return send({ ...good, origin: "https://other.test" });
    // Replies to requests that were never made, and messages that are not
    // replies; the request itself is then turned down.
    case "other-request": send({ ...good, requestId: "another-request" }); return deny();
    case "extra-field": send({ ...good, note: "one field too many" }); return deny();
    case "missing-field": { const { password, ...rest } = good; void password; send(rest); return deny(); }
    case "wrong-kind": send({ ...good, username: 7 }); return deny();
    case "unknown-type": send({ type: "fill", requestId, username: "fake-user", password: "fake-password" }); return deny();
    // Bytes that are not a message at all.
    case "garbage": return process.stdout.write(frame(Buffer.from("not json")));
    // The host's process ends without an answer.
    case "exit": return process.exit(0);
    // Says nothing more: the request stays waiting.
    case "silent": return;
    default: throw new Error(`unknown mode ${mode}`);
  }
}

let buffered = Buffer.alloc(0);
process.stdin.on("data", (chunk) => {
  buffered = Buffer.concat([buffered, chunk]);
  while (buffered.length >= 4 && buffered.length >= 4 + buffered.readUInt32LE(0)) {
    const length = buffered.readUInt32LE(0);
    const message = JSON.parse(buffered.subarray(4, 4 + length).toString());
    buffered = buffered.subarray(4 + length);
    log(JSON.stringify(message));
    if (message.type === "fill_request") answer(message);
  }
});
process.stdin.on("end", () => { log("closed"); process.exit(0); });
