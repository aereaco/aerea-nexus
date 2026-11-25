export interface SyncTransform {
  file: string;
  description: string;
  transform: (content: string) => string;
}

export interface GeneratedFile {
  path: string;
  description: string;
  content: string;
}

export interface SyncTargetConfig {
  name: string;
  targetDir: string;
  githubRepo: string;
  branch?: string;
  sourcePrefix?: string;
  cloudflareProject?: string;
  includes: string[];
  excludes: string[];
  transforms?: SyncTransform[];
  generatedFiles?: GeneratedFile[];
  runManifest?: boolean;
}

const stripShellOnlyBlocks = (content: string): string =>
  content.replace(/\s*<!--\s*\[SYNC:SHELL-ONLY:START\]\s*-->[\s\S]*?<!--\s*\[SYNC:SHELL-ONLY:END\]\s*-->/g, "");

export const syncConfig: Record<string, SyncTargetConfig> = {
  "nexus-ux": {
    name: "Nexus-UX Core Runtime Engine",
    targetDir: "../nexus-ux",
    githubRepo: "aereaco/nexus-ux",
    includes: [
      "src/**",
      "dist/**",
      "scripts/build.ts",
      "deno.json",
      "deno.lock",
      "README.md",
      "LICENSE",
      "changelog.md",
      ".gitignore",
      ".gitattributes",
    ],
    excludes: [
      "site/**",
      "scripts/serve.ts",
      "scripts/generate_labs.ts",
      "scripts/git/**",
      "scripts/sync/**",
    ],
    transforms: [
      {
        file: "deno.json",
        description: "Prune site/sync tasks for pure engine repository",
        transform: (content: string) => {
          try {
            const parsed = JSON.parse(content);
            parsed.tasks = {
              build: "deno run -A scripts/build.ts --minify",
              test: "deno test -A src/",
              "build:push": "deno run -A scripts/build.ts --minify --push",
            };
            return JSON.stringify(parsed, null, 2) + "\n";
          } catch {
            return content;
          }
        },
      },
    ],
    runManifest: false,
  },

  "nexus-site": {
    name: "Nexus-UX Public Documentation & Labs Portal",
    targetDir: "../nexus-site",
    githubRepo: "aereaco/nexus-site",
    cloudflareProject: "nexus-site",
    includes: [
      "site/_pages/docs/**",
      "site/_pages/labs/**",
      "site/_pages/home.html",
      "site/_pages/error.html",
      "site/_components/**",
      "site/_assets/**",
      "site/index.html",
      "site/sw.js",
      "dist/**",
      "scripts/serve.ts",
      "scripts/git/manifest.ts",
      "deno.json",
      "README.md",
      "LICENSE",
      ".gitignore",
      ".gitattributes",
    ],
    excludes: [
      "site/_pages/apps/**",
      "site/_pages/_internal/**",
      "site/_components/layout-terminal.html",
      "site/_components/layout-chatbar.html",
      "site/_components/layout-chat-fab.html",
      "site/_components/layout-dropdowns.html",
      "site/_components/layout-notifications.html",
      "site/_components/layout-mail.html",
      "site/_components/layout-cart.html",
      "site/_components/layout-profile.html",
    ],
    transforms: [
      {
        file: "site/_components/layout.html",
        description: "Strip shell-only component mounts (Terminal HUD, Chatbar, Chat FAB, Dropdowns)",
        transform: stripShellOnlyBlocks,
      },
      {
        file: "site/_components/layout-header.html",
        description: "Strip shell-only navbar controls (Megamenu, Terminal HUD, Mail, Cart, Notifications, Profile)",
        transform: stripShellOnlyBlocks,
      },
      {
        file: "site/_pages/home.html",
        description: "Point hero secondary action button to Interactive Labs index in public docs portal",
        transform: (content: string) =>
          content.replace(
            /<a href="\/flow" data-tab-title="Flow Canvas"/g,
            '<a href="/labs/attributes" data-tab-title="Attributes"'
          ),
      },
      {
        file: "deno.json",
        description: "Configure dev server & manifest tasks for nexus-site",
        transform: (content: string) => {
          try {
            const parsed = JSON.parse(content);
            parsed.tasks = {
              serve: "deno run -A scripts/serve.ts",
              "serve:progressive": "deno run -A scripts/serve.ts --mode progressive",
              manifest: "deno run -A scripts/git/manifest.ts",
            };
            return JSON.stringify(parsed, null, 2) + "\n";
          } catch {
            return content;
          }
        },
      },
    ],
    runManifest: true,
  },

  "nexus-shell": {
    name: "Nexus-UX Workbench Application Shell Starter",
    targetDir: "../nexus-shell",
    githubRepo: "aereaco/nexus-shell",
    cloudflareProject: "nexus-shell",
    includes: [
      "site/_components/**",
      "site/_assets/**",
      "site/index.html",
      "site/sw.js",
      "site/_pages/error.html",
      "dist/**",
      "scripts/serve.ts",
      "scripts/git/manifest.ts",
      "deno.json",
      "README.md",
      "LICENSE",
      ".gitignore",
      ".gitattributes",
    ],
    excludes: [
      "site/_pages/docs/**",
      "site/_pages/labs/**",
      "site/_pages/apps/**",
      "site/_pages/_internal/**",
      "site/_components/lab-viewer.html",
    ],
    generatedFiles: [
      {
        path: "site/_pages/home.html",
        description: "Clean Workbench Shell Starter landing page",
        content: `<head>
  <title>Home</title>
  <meta name="route" content="/">
  <meta name="icon" content="material-symbols-light:home-outline">
  <meta name="order" content="1">
</head>

<div class="max-w-5xl mx-auto w-full space-y-8 py-6" data-signal="{ counter: 1 }">
  <div class="rounded-3xl bg-gradient-to-br from-base-200/90 via-base-100 to-base-200/50 p-8 md:p-10 border border-base-content/10 shadow-xl space-y-5">
    <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/25 text-primary text-xs font-semibold uppercase tracking-wider">
      <span class="inline-block size-2 rounded-full bg-primary animate-pulse"></span>
      Nexus-Shell Starter Workspace
    </div>
    <h1 class="text-3xl sm:text-4xl font-black tracking-tight">
      Desktop-Class Web Application Shell
    </h1>
    <p class="text-base text-base-content/75 max-w-2xl leading-relaxed">
      Welcome to <strong>Nexus-Shell</strong> — the standalone multi-tab application workbench powered by <strong>Nexus-UX</strong>. Drop HTML pages into <code>site/_pages/</code> to automatically register routes, sidebar navigation, search indexing, and multi-tab workspaces.
    </p>
    <div class="flex flex-wrap items-center gap-3 pt-2">
      <button type="button" class="btn btn-primary btn-sm gap-2" data-on-click="if (typeof toggleTerminalHud === 'function') toggleTerminalHud()">
        <iconify-icon icon="material-symbols-light:terminal" class="text-lg"></iconify-icon>
        Toggle Terminal HUD
      </button>
      <button type="button" class="btn btn-secondary btn-sm gap-2" data-on-click="chatbarOpen = !chatbarOpen">
        <iconify-icon icon="material-symbols-light:smart-toy-outline" class="text-lg"></iconify-icon>
        Toggle AI Chatbar
      </button>
      <button type="button" class="btn btn-accent btn-sm gap-2" data-on-click="notify('Workbench Ready', 'Declarative notification dispatched #' + (counter++), 'success')">
        <iconify-icon icon="material-symbols-light:notifications-active-outline" class="text-lg"></iconify-icon>
        Test Notification
      </button>
      <button type="button" class="btn btn-outline btn-sm gap-2" data-on-click="router.createPageTab('_components/tab-new.html')">
        <iconify-icon icon="material-symbols-light:tab-group-outline" class="text-lg"></iconify-icon>
        Open New Tab
      </button>
    </div>
  </div>
</div>
`,
      },
    ],
    transforms: [
      {
        file: "deno.json",
        description: "Configure dev server & manifest tasks for nexus-shell",
        transform: (content: string) => {
          try {
            const parsed = JSON.parse(content);
            parsed.tasks = {
              serve: "deno run -A scripts/serve.ts",
              "serve:progressive": "deno run -A scripts/serve.ts --mode progressive",
              manifest: "deno run -A scripts/git/manifest.ts",
            };
            return JSON.stringify(parsed, null, 2) + "\n";
          } catch {
            return content;
          }
        },
      },
    ],
    runManifest: true,
  },

  "nexus-io": {
    name: "Nexus-IO Sovereign Binary & nexus-db Engine",
    targetDir: "../nexus-io",
    githubRepo: "aereaco/nexus-io",
    branch: "main",
    sourcePrefix: "io/",
    includes: [
      "io/Cargo.toml",
      "io/Cargo.lock",
      "io/.cargo/**",
      "io/src/**",
      "io/crates/**",
      "io/docs/**",
      "io/tests/**",
      "io/LICENSE",
      "io/README.md",
      "io/.gitignore",
    ],
    excludes: [
      "io/target/**",
      "io/nexus-blobs/**",
      "io/nexus.db/**",
      "io/**/*.bin",
    ],
    runManifest: false,
  },
};
