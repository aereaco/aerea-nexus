import * as path from "std/path";
import { walk } from "https://deno.land/std@0.212.0/fs/walk.ts";
import { syncConfig, type SyncTargetConfig } from "./sync.config.ts";
import { publishToCloudflare } from "../build.ts";

function globToRegExp(glob: string): RegExp {
  const normalized = glob.replace(/\\/g, "/");
  let regexStr = "^";
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized[i];
    if (ch === "*") {
      if (normalized[i + 1] === "*") {
        if (normalized[i + 2] === "/") {
          regexStr += "(?:.*/)?";
          i += 2;
        } else {
          regexStr += ".*";
          i += 1;
        }
      } else {
        regexStr += "[^/]*";
      }
    } else if (".+?^${}()|[]\\".includes(ch)) {
      regexStr += "\\" + ch;
    } else {
      regexStr += ch;
    }
  }
  regexStr += "$";
  return new RegExp(regexStr);
}

const TEXT_EXTS = new Set([".rs", ".ts", ".js", ".md", ".toml", ".json", ".ps1", ".html", ".css", ".yml", ".yaml"]);
const MOJIBAKE_RE = /\u00F0\u0178|\u00E2\u2020|\u00E2\u20AC|\u00E2\u0153|\u00E2\u0161|\u00C3\u2014|\u00C2\u00A7/;
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

function assertCleanUtf8(bytes: Uint8Array, relPath: string): void {
  const ext = path.extname(relPath).toLowerCase();
  if (!TEXT_EXTS.has(ext)) return;
  let text: string;
  try {
    text = STRICT_UTF8.decode(bytes);
  } catch {
    throw new Error(`[encoding-guard] Invalid UTF-8 byte sequence detected in '${relPath}'`);
  }
  if (text.includes("\uFFFD")) {
    throw new Error(`[encoding-guard] Unicode replacement character (U+FFFD) detected in '${relPath}'`);
  }
  if (MOJIBAKE_RE.test(text)) {
    throw new Error(`[encoding-guard] Known UTF-8/CP1252 mojibake signature detected in '${relPath}'`);
  }
}

function runGit(args: string[], cwd: string): { ok: boolean; out: string; err: string } {
  const res = new Deno.Command("git", { args, cwd }).outputSync();
  return {
    ok: res.success,
    out: new TextDecoder().decode(res.stdout).trim(),
    err: new TextDecoder().decode(res.stderr).trim(),
  };
}

function mapSourceToDest(rel: string, cfg: SyncTargetConfig): string {
  if (cfg.pathMappings) {
    for (const m of cfg.pathMappings) {
      const from = m.fromPrefix.replace(/\\/g, "/");
      const to = m.toPrefix.replace(/\\/g, "/");
      if (rel.startsWith(from)) {
        return to + rel.slice(from.length);
      }
    }
  }
  const prefix = cfg.sourcePrefix ? cfg.sourcePrefix.replace(/\\/g, "/") : "";
  if (prefix && rel.startsWith(prefix)) {
    return rel.slice(prefix.length);
  }
  return rel;
}

function mapDestToSource(destRel: string, cfg: SyncTargetConfig): string | null {
  if (cfg.pathMappings) {
    for (const m of cfg.pathMappings) {
      const from = m.fromPrefix.replace(/\\/g, "/");
      const to = m.toPrefix.replace(/\\/g, "/");
      if (destRel.startsWith(to)) {
        const candidate = from + destRel.slice(to.length);
        if (!cfg.pullPrefix || candidate.startsWith(cfg.pullPrefix)) {
          return candidate;
        }
      }
    }
  }
  const prefix = cfg.sourcePrefix ? cfg.sourcePrefix.replace(/\\/g, "/") : "";
  const candidate = prefix ? prefix + destRel : destRel;
  if (cfg.pullPrefix && !candidate.startsWith(cfg.pullPrefix)) {
    return null;
  }
  return candidate;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Keep `io/docs/*` and `docs/io/*` synchronized bidirectionally inside the monorepo.
 */
async function syncInternalDocsMirror(sourceRoot: string): Promise<void> {
  for (const docName of ["architecture.md", "benchmarks.md"]) {
    const ioDoc = path.join(sourceRoot, "io", "docs", docName);
    const unifiedDoc = path.join(sourceRoot, "docs", "io", docName);
    try {
      const ioStat = await Deno.stat(ioDoc).catch(() => null);
      const uniStat = await Deno.stat(unifiedDoc).catch(() => null);
      if (ioStat && uniStat) {
        const ioMtime = ioStat.mtime?.getTime() ?? 0;
        const uniMtime = uniStat.mtime?.getTime() ?? 0;
        if (ioMtime >= uniMtime) {
          await Deno.copyFile(ioDoc, unifiedDoc);
        } else {
          await Deno.copyFile(unifiedDoc, ioDoc);
        }
      } else if (ioStat && !uniStat) {
        await Deno.mkdir(path.dirname(unifiedDoc), { recursive: true });
        await Deno.copyFile(ioDoc, unifiedDoc);
      } else if (!ioStat && uniStat) {
        await Deno.mkdir(path.dirname(ioDoc), { recursive: true });
        await Deno.copyFile(unifiedDoc, ioDoc);
      }
    } catch {
      // ignore
    }
  }
}

async function cleanTargetTree(targetRoot: string, allowedRelPaths: Set<string>): Promise<void> {
  try {
    const toDelete: string[] = [];
    for await (const entry of walk(targetRoot, { includeDirs: false })) {
      const rel = path.relative(targetRoot, entry.path).replace(/\\/g, "/");
      if (
        rel.startsWith(".git/") ||
        rel === ".git" ||
        rel.startsWith(".nexus/") ||
        rel.startsWith(".wrangler/") ||
        rel.startsWith("node_modules/") ||
        rel.startsWith("target/")
      ) {
        continue;
      }
      if (!allowedRelPaths.has(rel)) {
        toDelete.push(entry.path);
      }
    }
    for (const file of toDelete) {
      try {
        await Deno.remove(file);
      } catch {
        // ignore
      }
    }
  } catch {
    // targetRoot may not exist yet
  }
}

/**
 * Two-Way Pull (`--pull`): Propagate changes from a downstream domain repository back into `aerea-nexus`.
 */
async function pullFromTarget(
  key: string,
  cfg: SyncTargetConfig,
  sourceRoot: string
): Promise<number> {
  const targetRoot = path.resolve(sourceRoot, cfg.targetDir);
  try {
    const st = await Deno.stat(targetRoot);
    if (!st.isDirectory) return 0;
  } catch {
    console.log(`   ℹ️  Skipping pull for [${key}] (${targetRoot} not initialized locally)`);
    return 0;
  }

  console.log(`\n============================================================`);
  console.log(`⬇️  Pulling [${key}] ← ${cfg.name}`);
  console.log(`   Downstream: ${targetRoot}`);
  console.log(`   Upstream:   ${sourceRoot}`);
  console.log(`============================================================`);

  const includeRegexes = cfg.includes.map(globToRegExp);
  const excludeRegexes = cfg.excludes.map(globToRegExp);
  const transformSet = new Set((cfg.transforms || []).map((t) => t.file.replace(/\\/g, "/")));
  const generatedSet = new Set((cfg.generatedFiles || []).map((g) => g.path.replace(/\\/g, "/")));

  let updatedCount = 0;

  for await (const entry of walk(targetRoot, { includeDirs: false })) {
    const destRel = path.relative(targetRoot, entry.path).replace(/\\/g, "/");
    if (
      destRel.startsWith(".git/") ||
      destRel.startsWith(".nexus/") ||
      destRel.startsWith("node_modules/") ||
      destRel.startsWith(".wrangler/") ||
      destRel.startsWith("target/")
    ) {
      continue;
    }
    if (transformSet.has(destRel) || generatedSet.has(destRel)) {
      continue;
    }

    const srcRel = mapDestToSource(destRel, cfg);
    if (!srcRel) continue;
    if (!includeRegexes.some((rx) => rx.test(srcRel))) continue;
    if (excludeRegexes.some((rx) => rx.test(srcRel))) continue;

    const downBytes = await Deno.readFile(entry.path);
    assertCleanUtf8(downBytes, `${key}:${destRel}`);

    const upPath = path.join(sourceRoot, srcRel);
    let upBytes: Uint8Array | null = null;
    try {
      upBytes = await Deno.readFile(upPath);
    } catch {
      upBytes = null;
    }

    if (!upBytes || !bytesEqual(downBytes, upBytes)) {
      // Only pull if downstream file mtime is newer than upstream (or upstream doesn't exist)
      const downStat = await Deno.stat(entry.path);
      const upStat = await Deno.stat(upPath).catch(() => null);
      const downMtime = downStat.mtime?.getTime() ?? 0;
      const upMtime = upStat?.mtime?.getTime() ?? 0;
      if (!upStat || downMtime > upMtime) {
        await Deno.mkdir(path.dirname(upPath), { recursive: true });
        await Deno.writeFile(upPath, downBytes);
        console.log(`   ⬇️  Pulled updated file: ${srcRel} (from ${key}/${destRel})`);
        updatedCount++;
      }
    }
  }

  await syncInternalDocsMirror(sourceRoot);
  console.log(`   ✓ Pull complete for [${key}]: ${updatedCount} file(s) updated in aerea-nexus`);
  return updatedCount;
}

async function syncTarget(
  key: string,
  cfg: SyncTargetConfig,
  sourceRoot: string,
  opts: { commit?: boolean; push?: boolean; publish?: boolean; pull?: boolean }
): Promise<void> {
  await syncInternalDocsMirror(sourceRoot);

  if (opts.pull) {
    await pullFromTarget(key, cfg, sourceRoot);
    return;
  }

  const targetRoot = path.resolve(sourceRoot, cfg.targetDir);
  console.log(`\n============================================================`);
  console.log(`🔄 Syncing [${key}] → ${cfg.name}`);
  console.log(`   Source: ${sourceRoot}`);
  console.log(`   Target: ${targetRoot}`);
  console.log(`============================================================`);

  await Deno.mkdir(targetRoot, { recursive: true });

  const includeRegexes = cfg.includes.map(globToRegExp);
  const excludeRegexes = cfg.excludes.map(globToRegExp);
  const transformMap = new Map((cfg.transforms || []).map((t) => [t.file.replace(/\\/g, "/"), t]));

  const syncedRelPaths = new Set<string>();
  let copiedCount = 0;

  for await (const entry of walk(sourceRoot, { includeDirs: false })) {
    const rel = path.relative(sourceRoot, entry.path).replace(/\\/g, "/");
    if (
      rel.startsWith(".git/") ||
      rel.startsWith(".nexus/") ||
      rel.startsWith("node_modules/") ||
      rel.startsWith(".wrangler/") ||
      rel.startsWith("target/") ||
      rel.startsWith("io/target/")
    ) {
      continue;
    }

    const included = includeRegexes.some((rx) => rx.test(rel));
    if (!included) continue;
    const excluded = excludeRegexes.some((rx) => rx.test(rel));
    if (excluded) continue;

    const destRel = mapSourceToDest(rel, cfg);
    const destPath = path.join(targetRoot, destRel);
    await Deno.mkdir(path.dirname(destPath), { recursive: true });

    const rawBytes = await Deno.readFile(entry.path);
    assertCleanUtf8(rawBytes, rel);

    const transformRule = transformMap.get(destRel) || transformMap.get(rel);
    if (transformRule) {
      const raw = STRICT_UTF8.decode(rawBytes);
      const transformed = transformRule.transform(raw);
      await Deno.writeTextFile(destPath, transformed);
      console.log(`   ✂️  Transformed: ${destRel} (${transformRule.description})`);
    } else {
      await Deno.copyFile(entry.path, destPath);
    }

    syncedRelPaths.add(destRel);
    copiedCount++;
  }

  if (cfg.generatedFiles) {
    for (const gen of cfg.generatedFiles) {
      const rel = gen.path.replace(/\\/g, "/");
      const destPath = path.join(targetRoot, rel);
      await Deno.mkdir(path.dirname(destPath), { recursive: true });
      await Deno.writeTextFile(destPath, gen.content);
      syncedRelPaths.add(rel);
      console.log(`   ✨ Generated: ${rel} (${gen.description})`);
    }
  }

  if (cfg.runManifest) {
    syncedRelPaths.add("site/_pages/manifest.json");
    syncedRelPaths.add("site/_pages/search-index.json");
  }

  await cleanTargetTree(targetRoot, syncedRelPaths);
  console.log(`   ✓ Mirrored ${copiedCount} file(s) to ${targetRoot}`);

  if (cfg.runManifest) {
    console.log(`   🗂️  Re-indexing manifest.json & search-index.json in ${key}...`);
    const manifestCmd = new Deno.Command(Deno.execPath(), {
      args: ["run", "-A", "scripts/git/manifest.ts"],
      cwd: targetRoot,
      stdout: "inherit",
      stderr: "inherit",
    });
    const res = await manifestCmd.output();
    if (!res.success) {
      throw new Error(`Manifest generation failed in ${targetRoot}`);
    }
  }

  if (opts.commit || opts.push || opts.publish) {
    const gitDir = path.join(targetRoot, ".git");
    let hasGit = false;
    try {
      const st = await Deno.stat(gitDir);
      hasGit = st.isDirectory;
    } catch {
      hasGit = false;
    }

    const branch = cfg.branch || "main";
    if (!hasGit) {
      console.log(`   🌱 Initializing git repository in ${targetRoot}...`);
      runGit(["init", "-b", branch], targetRoot);
    } else {
      const curBranch = runGit(["rev-parse", "--abbrev-ref", "HEAD"], targetRoot).out;
      if (curBranch && curBranch !== branch) {
        console.log(`   🌿 Switching ${key} branch ${curBranch} → ${branch}...`);
        const sw = runGit(["checkout", "-B", branch], targetRoot);
        if (!sw.ok) {
          console.warn(`   ⚠️ Branch switch note in ${key}: ${sw.err || sw.out}`);
        }
      }
    }

    const remoteUrl = `https://github.com/${cfg.githubRepo}.git`;
    const curRemote = runGit(["remote", "get-url", "origin"], targetRoot);
    if (!curRemote.ok) {
      runGit(["remote", "add", "origin", remoteUrl], targetRoot);
    } else if (curRemote.out !== remoteUrl) {
      runGit(["remote", "set-url", "origin", remoteUrl], targetRoot);
    }

    const sourceSha = runGit(["rev-parse", "--short", "HEAD"], sourceRoot).out || "head";
    runGit(["add", "-A"], targetRoot);
    const status = runGit(["status", "--porcelain"], targetRoot);
    if (status.out) {
      const commitMsg = `sync(ssot): propagate platform updates [ref: aerea-nexus@${sourceSha}]`;
      const cRes = runGit(["commit", "-m", commitMsg], targetRoot);
      if (cRes.ok) {
        console.log(`   ✓ Committed in ${key}: "${commitMsg}"`);
      } else {
        console.warn(`   ⚠️ Commit note in ${key}: ${cRes.err || cRes.out}`);
      }
    } else {
      console.log(`   ℹ️  No file diffs to commit in ${key}.`);
    }

    if (opts.push || opts.publish) {
      console.log(`   🚀 Pushing ${key} → ${remoteUrl} (${branch})...`);
      const pRes = runGit(["push", "-u", "origin", branch, "--force"], targetRoot);
      if (pRes.ok || /up[- ]to[- ]date/i.test(pRes.err + pRes.out)) {
        console.log(`   ✓ Pushed ${key} to GitHub (${cfg.githubRepo})`);
        if (key === "nexus-ux") {
          console.log(`   🧹 Purging jsDelivr CDN cache for ${cfg.githubRepo}...`);
          for (const asset of [
            `gh/${cfg.githubRepo}@main/dist/nexus-ux.min.js`,
            `gh/${cfg.githubRepo}@main/dist/nexus-ux.min.js.br`,
            `gh/${cfg.githubRepo}@main/dist/nexus-ux.js`,
          ]) {
            try {
              await fetch(`https://purge.jsdelivr.net/${asset}`);
            } catch {
              // ignore
            }
          }
        }
      } else {
        console.error(`   ❌ Failed to push ${key}: ${pRes.err || pRes.out}`);
      }
    }
  }

  if (opts.publish && cfg.cloudflareProject) {
    const prevCwd = Deno.cwd();
    try {
      Deno.chdir(targetRoot);
      await publishToCloudflare({ projectName: cfg.cloudflareProject, branch: "main" });
    } finally {
      Deno.chdir(prevCwd);
    }
  }
}

if (import.meta.main) {
  const args = Deno.args;
  const targetArg = args.find((a) => a.startsWith("--target="))?.split("=")[1] || "all";
  const pull = args.includes("--pull");
  const commit = args.includes("--commit") || args.includes("--push") || args.includes("--publish");
  const push = args.includes("--push") || args.includes("--publish");
  const publish = args.includes("--publish");

  const sourceRoot = Deno.cwd();
  const targets =
    targetArg === "all"
      ? Object.keys(syncConfig)
      : targetArg.split(",").map((t) => t.trim()).filter(Boolean);

  for (const t of targets) {
    const cfg = syncConfig[t];
    if (!cfg) {
      console.error(`Unknown sync target: "${t}". Available: ${Object.keys(syncConfig).join(", ")}`);
      Deno.exit(1);
    }
    await syncTarget(t, cfg, sourceRoot, { commit, push, publish, pull });
  }

  console.log(`\n✅ SSoT ${pull ? "two-way pull" : "synchronization"} complete for: ${targets.join(", ")}`);
}
