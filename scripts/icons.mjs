// Draws the app's icon, from the one drawing below, in every size and shape
// the apps and stores take, and writes each where its build takes it:
//
//   packaging/icon/                    the drawings, as SVG
//   apps/desktop/src-tauri/icons/      the desktop app: macOS .icns, Windows .ico, Linux PNGs
//   apps/desktop/src/BrandMark.tsx     the mark in the desktop window
//   apps/browser-extension/icons/      the extension, 16 to 128 px
//   apps/browser-extension/store/      the Chrome Web Store's icon and tile
//   apps/mobile/android/.../res/       Android: the adaptive icon (vector
//                                      drawables), and PNGs where it is not used
//   apps/mobile/ios/.../AppIcon.appiconset/icon-1024.png
//   fastlane/metadata/android/en-US/images/icon.png  F-Droid's listing
//
//   node scripts/icons.mjs
//
// Needs Playwright's Chromium (`npm ci` in apps/browser-extension) to draw
// the PNGs, and macOS's iconutil for the .icns.
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { crc32, deflateSync } from "node:zlib";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { chromium } = await import(path.join(root, "apps/browser-extension/node_modules/playwright/index.mjs"));
const at = (relative) => path.join(root, relative);

const AMBER = "#DDA45B";
const INK = "#17130E";
const CREAM = "#F4ECE0";

// On a 2048-unit square: a shield, a keyhole cut through it, and three
// devices joined into a triangle around the keyhole.
const SHIELD = "M1024 341Q774 520 424 555C420 1205 544 1471 1024 1706C1504 1471 1628 1205 1624 555Q1274 520 1024 341Z";
const KEYHOLE = "M972 1026A111 111 0 1 1 1076 1026L1119 1228H929Z";
const NODES = [[1024, 508], [570, 1285], [1478, 1285]];
const TRIANGLE = "M1024 508L570 1285H1478Z";
const circle = ([cx, cy], r) => `<circle cx="${cx}" cy="${cy}" r="${r}"/>`;

/**
 * The mark itself, at three levels of detail: "full"; "small", for about
 * 32 px, without the inner line and with the rest thicker; and "tiny", for
 * 16 px, the shield and its keyhole alone, as the triangle cannot be drawn
 * there.
 */
function symbol(level = "full") {
  if (level === "tiny") {
    return `<g transform="translate(1024 1024) scale(1.2) translate(-1024 -1024)">`
      + `<path d="${SHIELD}" fill="${INK}"/>`
      + `<path d="${KEYHOLE}" fill="${AMBER}" transform="translate(1024 1023) scale(1.35) translate(-1024 -1023)"/></g>`;
  }
  if (level === "small") {
    return `<g transform="translate(1024 1024) scale(1.12) translate(-1024 -1024)">`
      + `<path d="${SHIELD}" fill="${INK}"/>`
      + `<g fill="${INK}">${circle(NODES[1], 170)}${circle(NODES[2], 170)}</g>`
      + `<path d="${TRIANGLE}" fill="none" stroke="${CREAM}" stroke-width="64" stroke-linejoin="round"/>`
      + `<g fill="${CREAM}">${NODES.map((node) => circle(node, 110)).join("")}</g>`
      + `<path d="${KEYHOLE}" fill="${AMBER}"/></g>`;
  }
  return `<path d="${SHIELD}" fill="${INK}"/>`
    + `<path d="${SHIELD}" fill="none" stroke="${AMBER}" stroke-width="42.5" transform="translate(1024 1041) scale(.8) translate(-1024 -1041)"/>`
    + `<g fill="${INK}">${circle(NODES[0], 100)}${circle(NODES[1], 97)}${circle(NODES[2], 97)}</g>`
    + `<path d="${TRIANGLE}" fill="none" stroke="${CREAM}" stroke-width="24" stroke-linejoin="round"/>`
    + `<g fill="${CREAM}">${NODES.map((node) => circle(node, 57)).join("")}</g>`
    + `<path d="${KEYHOLE}" fill="${AMBER}"/>`;
}

const svg = (viewBox, body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}">${body}</svg>\n`;
/** Full bleed, for the systems that round the corners themselves (iOS). */
const square = (level) => svg("0 0 2048 2048", `<rect width="2048" height="2048" fill="${AMBER}"/>${symbol(level)}`);
/** A rounded square filling the canvas: the extension, Linux, F-Droid, the window. */
const rounded = (level) => svg("0 0 2048 2048", `<rect width="2048" height="2048" rx="460" fill="${AMBER}"/>${symbol(level)}`);
/** macOS's shape: a rounded square of 824 in 1024, with its shadow; macOS does not round icons. */
const macos = (level) => svg("0 0 1024 1024",
  `<defs><filter id="shadow" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="10" stdDeviation="12" flood-color="#000" flood-opacity=".3"/></filter></defs>`
  + `<rect x="100" y="100" width="824" height="824" rx="185" fill="${AMBER}" filter="url(#shadow)"/>`
  + `<g transform="translate(100 100) scale(${824 / 2048})">${symbol(level)}</g>`);
/** The level of detail for an icon of `pixels` across. */
const detail = (pixels) => (pixels <= 16 ? "tiny" : pixels <= 40 ? "small" : "full");

/** A PNG of RGBA pixels, with or without its alpha channel. */
function png(width, height, rgba, alpha = true) {
  const channels = alpha ? 4 : 3;
  const line = width * channels + 1;
  const raw = Buffer.alloc(line * height);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const from = (y * width + x) * 4;
      const to = y * line + 1 + x * channels;
      for (let c = 0; c < channels; c++) raw[to + c] = rgba[from + c];
    }
  }
  const chunk = (type, data) => {
    const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body) >>> 0);
    return Buffer.concat([length, body, crc]);
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = alpha ? 6 : 2;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

const browser = await chromium.launch();
const page = await browser.newPage();
/** Draws an SVG at width x height (centered at `inset` from each edge, if given) and writes it as a PNG. */
async function draw(file, drawing, width, height = width, { alpha = true, inset = 0 } = {}) {
  const pixels = await page.evaluate(async ({ drawing, width, height, inset }) => {
    const image = new Image();
    image.src = `data:image/svg+xml;base64,${btoa(drawing)}`;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d");
    context.drawImage(image, inset, inset, width - 2 * inset, height - 2 * inset);
    return Array.from(context.getImageData(0, 0, width, height).data);
  }, { drawing, width, height, inset });
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, png(width, height, pixels, alpha));
}

try {
  // The drawings.
  await mkdir(at("packaging/icon"), { recursive: true });
  for (const [name, text] of [["icon.svg", rounded("full")], ["icon-small.svg", rounded("small")], ["icon-tiny.svg", rounded("tiny")], ["icon-square.svg", square("full")], ["icon-macos.svg", macos("full")]]) {
    await writeFile(at(`packaging/icon/${name}`), text);
  }

  // The desktop app: macOS takes the .icns, a Linux package the PNGs.
  const iconset = await mkdtemp(path.join(tmpdir(), "osm-icon-"));
  const set = path.join(iconset, "icon.iconset");
  for (const size of [16, 32, 128, 256, 512]) {
    await draw(path.join(set, `icon_${size}x${size}.png`), macos(detail(size)), size);
    await draw(path.join(set, `icon_${size}x${size}@2x.png`), macos(detail(size * 2)), size * 2);
  }
  execFileSync("iconutil", ["-c", "icns", set, "-o", at("apps/desktop/src-tauri/icons/icon.icns")]);
  await rm(iconset, { recursive: true, force: true });
  await draw(at("apps/desktop/src-tauri/icons/32x32.png"), rounded(detail(32)), 32);
  await draw(at("apps/desktop/src-tauri/icons/128x128.png"), rounded("full"), 128);
  await draw(at("apps/desktop/src-tauri/icons/128x128@2x.png"), rounded("full"), 256);
  await draw(at("apps/desktop/src-tauri/icons/icon.png"), rounded("full"), 512);

  // Windows takes one .ico with the sizes in it, each as a PNG.
  // 32 first: Tauri takes the first as the window's own icon on Windows.
  const sizes = [32, 16, 48, 64, 128, 256];
  const images = [];
  for (const size of sizes) {
    const file = path.join(tmpdir(), `osm-ico-${process.pid}-${size}.png`);
    await draw(file, rounded(detail(size)), size);
    images.push(await readFile(file));
    await rm(file, { force: true });
  }
  const header = Buffer.alloc(6 + 16 * sizes.length);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(sizes.length, 4);
  let offset = header.length;
  sizes.forEach((size, i) => {
    const entry = 6 + 16 * i;
    header[entry] = size === 256 ? 0 : size;
    header[entry + 1] = size === 256 ? 0 : size;
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(images[i].length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += images[i].length;
  });
  await writeFile(at("apps/desktop/src-tauri/icons/icon.ico"), Buffer.concat([header, ...images]));

  // The mark in the desktop window's sidebar, as markup: the window's
  // content security policy loads no image from a data: address.
  const jsx = rounded("small").trim()
    .replace(/<svg xmlns="[^"]+" /, "<svg ")
    .replace(/ (stroke-width|stroke-linejoin)=/g, (_, name) => ` ${name.replace(/-(\w)/g, (__, c) => c.toUpperCase())}=`);
  await writeFile(at("apps/desktop/src/BrandMark.tsx"),
    `// The app's mark, drawn by scripts/icons.mjs: change it there.\n`
    + `export function BrandMark({ size }: { size: number }) {\n`
    + `  return (\n    ${jsx.replace("<svg ", `<svg aria-hidden="true" width={size} height={size} `)}\n  );\n}\n`);

  // The browser extension, and the Chrome Web Store's icon (96 px in 128,
  // as the store asks) and promotional tile.
  for (const size of [16, 32, 48, 128]) {
    await draw(at(`apps/browser-extension/icons/icon-${size}.png`), rounded(detail(size)), size);
  }
  await draw(at("apps/browser-extension/store/icon-store-128.png"), rounded("full"), 128, 128, { inset: 16 });
  const tile = await browser.newPage({ viewport: { width: 440, height: 280 }, deviceScaleFactor: 1 });
  await tile.setContent(`<style>
    html,body{margin:0;width:440px;height:280px;background:${INK};font-family:-apple-system,"Helvetica Neue",Helvetica,Arial,sans-serif;color:${CREAM}}
    .wrap{display:flex;align-items:center;gap:24px;padding:0 34px;height:280px;box-sizing:border-box}
    svg{width:112px;height:112px;flex:none}
    h1{margin:0 0 10px;font-size:27px;line-height:1.1;font-weight:700;letter-spacing:-0.3px;text-wrap:balance}
    p{margin:0;font-size:15px;line-height:1.45;color:${AMBER};text-wrap:balance}
  </style><div class="wrap">${rounded("full")}<div><h1>Open Secret Manager</h1><p>Fill logins, cards, and passkeys from your own devices. No account, no server.</p></div></div>`);
  await tile.screenshot({ path: at("apps/browser-extension/store/promo-tile-440x280.jpg"), type: "jpeg", quality: 92 });
  await tile.close();

  // Android's adaptive icon: the mark as a vector over the amber, inside the
  // 66 dp circle of the 108 dp layer that every launcher's mask keeps; and
  // one color of it, which Android 13 tints to the owner's theme.
  const res = "apps/mobile/android/app/src/main/res";
  const scale = 0.04;
  const group = `android:translateX="${(54 - 1024 * scale).toFixed(2)}" android:translateY="${(54 - 1023.5 * scale).toFixed(2)}" android:scaleX="${scale}" android:scaleY="${scale}"`;
  const disc = ([cx, cy], r) => `M${cx - r},${cy}a${r},${r} 0 1,0 ${2 * r},0a${r},${r} 0 1,0 ${-2 * r},0`;
  const vector = (body) => `<?xml version="1.0" encoding="utf-8"?>
<!-- Drawn by scripts/icons.mjs: change it there. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <group ${group}>
${body}
    </group>
</vector>
`;
  await mkdir(at(`${res}/drawable`), { recursive: true });
  await mkdir(at(`${res}/mipmap-anydpi-v26`), { recursive: true });
  await writeFile(at(`${res}/drawable/ic_launcher_foreground.xml`), vector([
    `        <path android:fillColor="${INK}" android:pathData="${SHIELD}" />`,
    `        <group android:pivotX="1024" android:pivotY="1041" android:scaleX="0.8" android:scaleY="0.8">`,
    `            <path android:strokeColor="${AMBER}" android:strokeWidth="42.5" android:pathData="${SHIELD}" />`,
    `        </group>`,
    `        <path android:fillColor="${INK}" android:pathData="${disc(NODES[0], 100)}${disc(NODES[1], 97)}${disc(NODES[2], 97)}" />`,
    `        <path android:strokeColor="${CREAM}" android:strokeWidth="24" android:strokeLineJoin="round" android:pathData="${TRIANGLE}" />`,
    `        <path android:fillColor="${CREAM}" android:pathData="${NODES.map((node) => disc(node, 57)).join("")}" />`,
    `        <path android:fillColor="${AMBER}" android:pathData="${KEYHOLE}" />`,
  ].join("\n")));
  await writeFile(at(`${res}/drawable/ic_launcher_monochrome.xml`), vector(
    `        <path android:fillColor="#FFFFFFFF" android:fillType="evenOdd" android:pathData="${SHIELD}${KEYHOLE}" />`));
  await writeFile(at(`${res}/values/ic_launcher_background.xml`), `<?xml version="1.0" encoding="utf-8"?>
<!-- The adaptive icon's background, from scripts/icons.mjs. -->
<resources>
    <color name="ic_launcher_background">${AMBER}</color>
</resources>
`);
  await writeFile(at(`${res}/mipmap-anydpi-v26/ic_launcher.xml`), `<?xml version="1.0" encoding="utf-8"?>
<!-- From scripts/icons.mjs. -->
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@drawable/ic_launcher_foreground" />
    <monochrome android:drawable="@drawable/ic_launcher_monochrome" />
</adaptive-icon>
`);

  // Android: where its adaptive icon is not used, the PNGs.
  for (const [density, size] of [["mdpi", 48], ["hdpi", 72], ["xhdpi", 96], ["xxhdpi", 144], ["xxxhdpi", 192]]) {
    await draw(at(`apps/mobile/android/app/src/main/res/mipmap-${density}/ic_launcher.png`), rounded("full"), size);
  }
  // iOS rounds the corners itself, and takes no alpha channel.
  await draw(at("apps/mobile/ios/App/Assets.xcassets/AppIcon.appiconset/icon-1024.png"), square("full"), 1024, 1024, { alpha: false });
  // F-Droid's listing.
  await draw(at("fastlane/metadata/android/en-US/images/icon.png"), rounded("full"), 512);
} finally {
  await browser.close();
}
console.log("icons drawn");
