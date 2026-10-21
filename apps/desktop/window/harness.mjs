// What the window tests share: the window as `npm run build` made it, served
// from `dist` by a small server of the test's own, and opened in headless
// WebKit, the engine that draws the window on macOS and Linux. Without the
// native shell the window runs as its browser preview (src/bridge.ts), on
// sample data, and its address asks for the states the preview otherwise
// never has: `?rows-changed`, `?recovery-key`, `?held`, `?conflict`, `?devices`,
// `?many`, `?backup-due`, and `?no-backup`.

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { webkit } from "playwright";

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.resolve(here, "../dist");

/** The window's first size and its smallest, as `src-tauri/tauri.conf.json` sets them. */
export const FIRST_SIZE = { width: 1200, height: 760 };
export const SMALLEST_SIZE = { width: 960, height: 680 };

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

async function serve() {
  if (!existsSync(path.join(dist, "index.html"))) throw new Error("build the window first: npm run build");
  const server = http.createServer(async (request, response) => {
    const { pathname } = new URL(request.url, "http://localhost");
    const file = path.join(dist, pathname === "/" ? "index.html" : decodeURIComponent(pathname));
    if (!file.startsWith(dist + path.sep)) {
      response.writeHead(403).end();
      return;
    }
    try {
      const body = await readFile(file);
      response.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "application/octet-stream" }).end(body);
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** Serves the window and starts WebKit, for one test file. */
export async function start() {
  const served = await serve();
  const browser = await webkit.launch();
  return {
    /**
     * Opens the window at `size`, its address ending in `query`, once its
     * items show. `errors` collects what the page threw.
     */
    async open(query = "", size = FIRST_SIZE) {
      const page = await browser.newPage({ viewport: size });
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.goto(`${served.origin}/${query}`);
      await page.locator(".entry-row").first().waitFor();
      return { page, errors };
    },
    async stop() {
      await browser.close();
      await served.close();
    },
  };
}

/** The titles of the items the list shows, in its order. */
export async function titles(page) {
  return page.locator(".entry-row strong").allTextContents();
}

/** Where `locator` is drawn: its left, top, right, and bottom edges. */
export async function edges(locator) {
  const box = await locator.boundingBox();
  if (!box) throw new Error("not drawn");
  return { left: box.x, top: box.y, right: box.x + box.width, bottom: box.y + box.height };
}

/** Whether the page can be scrolled sideways, which the window never should be. */
export async function scrollsSideways(page) {
  return page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
}
