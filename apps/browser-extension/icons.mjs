// Draws the extension's icons from the app's own: the sizes browsers ask
// for, as PNG files in icons/. The files are kept in the repository; this
// is run again only when the app's icon changes.
//
//   node icons.mjs
import { mkdir, readFile } from "node:fs/promises";
import { chromium } from "playwright";

const here = new URL(".", import.meta.url);
const drawing = await readFile(new URL("../desktop/src-tauri/icons/icon.svg", here), "utf8");
await mkdir(new URL("icons/", here), { recursive: true });

const browser = await chromium.launch();
try {
  for (const size of [16, 32, 48, 128]) {
    const page = await browser.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
    await page.setContent(`<style>html, body { margin: 0; background: transparent } svg { display: block; width: ${size}px; height: ${size}px }</style>${drawing}`);
    await page.screenshot({ path: decodeURIComponent(new URL(`icons/icon-${size}.png`, here).pathname), omitBackground: true });
    await page.close();
  }
} finally {
  await browser.close();
}
