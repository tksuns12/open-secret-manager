// Builds the extension for each browser into dist/<browser>: the two
// scripts, bundled from the one source, that browser's manifest, and the
// icons.
import { build } from "esbuild";
import { copyFile, cp, mkdir, rm } from "node:fs/promises";

const here = new URL(".", import.meta.url);

for (const browser of ["chromium", "firefox"]) {
  const out = new URL(`dist/${browser}/`, here);
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });
  await build({
    absWorkingDir: decodeURIComponent(here.pathname),
    entryPoints: ["src/background.ts", "src/content.ts"],
    outdir: `dist/${browser}`,
    bundle: true,
    // Plain scripts: a page script cannot be a module, and neither browser
    // needs the background to be one.
    format: "iife",
    target: "es2022",
    legalComments: "none",
    logLevel: "warning",
  });
  await copyFile(new URL(`manifest.${browser}.json`, here), new URL("manifest.json", out));
  await cp(new URL("icons/", here), new URL("icons/", out), { recursive: true });
}
