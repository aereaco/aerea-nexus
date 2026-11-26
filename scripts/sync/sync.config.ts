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

export interface PathMapping {
  fromPrefix: string;
  toPrefix: string;
}

export interface SyncTargetConfig {
  name: string;
  targetDir: string;
  githubRepo: string;
  branch?: string;
  sourcePrefix?: string;
  pathMappings?: PathMapping[];
  pullPrefix?: string;
  cloudflareProject?: string;
  includes: string[];
  excludes: string[];
  transforms?: SyncTransform[];
  generatedFiles?: GeneratedFile[];
  runManifest?: boolean;
  appRepos?: Record<string, string>;
}

const configurePublicSiteShellFlags = (content: string): string =>
  content
    .replace(/mode:\s*'platform'/g, "mode: 'site'")
    .replace(/showMegamenu:\s*true/g, "showMegamenu: false")
    .replace(/showTerminal:\s*true/g, "showTerminal: false")
    .replace(/showChatbar:\s*true/g, "showChatbar: false")
    .replace(/showDropdowns:\s*true/g, "showDropdowns: false")
    .replace(/showMail:\s*true/g, "showMail: false")
    .replace(/showCart:\s*true/g, "showCart: false")
    .replace(/showNotifications:\s*true/g, "showNotifications: false")
    .replace(/showProfile:\s*true/g, "showProfile: false");

export const syncConfig: Record<string, SyncTargetConfig> = {
  "nexus-io": {
    name: "Nexus-IO Sovereign Microkernel & nexus-db Engine",
    targetDir: "../nexus-io",
    githubRepo: "aereaco/nexus-io",
    branch: "main",
    sourcePrefix: "io/",
    pullPrefix: "io/",
    includes: [
      "io/Cargo.toml",
      "io/Cargo.lock",
      "io/.cargo/**",
      "io/src/**",
      "io/crates/**",
      "io/docs/**",
      "io/scripts/**",
      "io/tests/**",
      "io/LICENSE",
      "io/README.md",
      "io/.gitignore",
    ],
    excludes: [
      "io/target/**",
      "io/.nexus/**",
      "io/nexus-blobs/**",
      "io/nexus.db/**",
      "io/**/*.redb",
      "io/**/*.bin",
    ],
    runManifest: false,
  },

  "nexus-ux": {
    name: "Nexus-UX Core Reactive Runtime Engine",
    targetDir: "../nexus-ux",
    githubRepo: "aereaco/nexus-ux",
    sourcePrefix: "ux/",
    pullPrefix: "ux/src/",
    pathMappings: [
      { fromPrefix: "ux/src/", toPrefix: "src/" },
      { fromPrefix: "ux/dist/", toPrefix: "dist/" },
      { fromPrefix: "docs/ux/", toPrefix: "docs/" },
    ],
    includes: [
      "ux/src/**",
      "ux/dist/**",
      "docs/ux/**",
      "scripts/build.ts",
      "deno.json",
      "deno.lock",
      "README.md",
      "LICENSE",
      "changelog.md",
      ".gitignore",
      ".gitattributes",
    ],
    excludes: [],
    transforms: [
      {
        file: "deno.json",
        description: "Configure tasks for standalone nexus-ux repository",
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

  "nexus-shell": {
    name: "Nexus-Shell Universal Responsive Application Workbench",
    targetDir: "../nexus-shell",
    githubRepo: "aereaco/nexus-shell",
    cloudflareProject: "nexus-shell",
    pullPrefix: "shell/",
    pathMappings: [
      { fromPrefix: "shell/", toPrefix: "site/" },
      { fromPrefix: "platform/_components/", toPrefix: "site/_components/" },
      { fromPrefix: "ux/dist/", toPrefix: "dist/" },
    ],
    includes: [
      "shell/**",
      "platform/_components/**",
      "ux/dist/**",
      "scripts/serve.ts",
      "scripts/git/manifest.ts",
      "deno.json",
      "README.md",
      "LICENSE",
      ".gitignore",
      ".gitattributes",
    ],
    excludes: [],
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
      Desktop-Class &amp; Mobile-First Application Shell
    </h1>
    <p class="text-base text-base-content/75 max-w-2xl leading-relaxed">
      Welcome to <strong>Nexus-Shell</strong> — the universal multi-tab application workbench powered by <strong>Nexus-UX</strong> and controlled declaratively via <code>shellConfig</code>.
    </p>
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

  "nexus-site": {
    name: "Nexus-Site Public Documentation & Labs Portal",
    targetDir: "../nexus-site",
    githubRepo: "aereaco/nexus-site",
    cloudflareProject: "nexus-site",
    pullPrefix: "site/",
    pathMappings: [
      { fromPrefix: "shell/", toPrefix: "site/" },
      { fromPrefix: "labs/_components/", toPrefix: "site/_components/" },
      { fromPrefix: "labs/", toPrefix: "site/_pages/labs/" },
      { fromPrefix: "docs/", toPrefix: "site/_pages/docs/" },
      { fromPrefix: "ux/dist/", toPrefix: "dist/" },
    ],
    includes: [
      "shell/**",
      "site/_pages/home.html",
      "labs/**",
      "docs/*.md",
      "ux/dist/**",
      "scripts/serve.ts",
      "scripts/git/manifest.ts",
      "deno.json",
      "README.md",
      "LICENSE",
      ".gitignore",
      ".gitattributes",
    ],
    excludes: [
      "docs/io/**",
      "docs/ux/**",
    ],
    transforms: [
      {
        file: "site/_components/layout.html",
        description: "Configure declarative shellConfig flags for public documentation portal",
        transform: configurePublicSiteShellFlags,
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

  "nexus-labs": {
    name: "Nexus-Labs 65 Interactive NEG Directive Sandboxes",
    targetDir: "../nexus-labs",
    githubRepo: "aereaco/nexus-labs",
    sourcePrefix: "labs/",
    pullPrefix: "labs/",
    includes: [
      "labs/**",
      "scripts/generate_labs.ts",
      "LICENSE",
    ],
    excludes: [],
    runManifest: false,
  },

  "nexus-platform": {
    name: "Nexus-Platform Turnkey OS Control Plane, IAM & Studio",
    targetDir: "../nexus-platform",
    githubRepo: "aereaco/nexus-platform",
    sourcePrefix: "platform/",
    pullPrefix: "platform/",
    includes: [
      "platform/**",
      "nexus.toml",
      "LICENSE",
    ],
    excludes: [],
    runManifest: false,
  },

  "nexus-apps": {
    name: "Nexus-Apps Turnkey ERP & Collaboration Fractal Monorepo",
    targetDir: "../nexus-apps",
    githubRepo: "aereaco/nexus-apps",
    sourcePrefix: "apps/",
    pullPrefix: "apps/",
    includes: [
      "apps/**",
      "LICENSE",
    ],
    excludes: [],
    appRepos: {
      erp: "aereaco/nexus-app-erp",
      drag: "aereaco/nexus-app-drag",
      todo: "aereaco/nexus-app-todo",
    },
    runManifest: false,
  },

  "nexus-docs": {
    name: "Nexus-Docs Unified Specifications, Architecture & Guides",
    targetDir: "../nexus-docs",
    githubRepo: "aereaco/nexus-docs",
    sourcePrefix: "docs/",
    pullPrefix: "docs/",
    includes: [
      "docs/**",
      "LICENSE",
    ],
    excludes: [],
    runManifest: false,
  },

  "nexus-scripts": {
    name: "Nexus-Scripts Build, Manifest, CI & SSoT Sync Tooling",
    targetDir: "../nexus-scripts",
    githubRepo: "aereaco/nexus-scripts",
    sourcePrefix: "scripts/",
    pullPrefix: "scripts/",
    includes: [
      "scripts/**",
      "deno.json",
      "LICENSE",
    ],
    excludes: [],
    runManifest: false,
  },
};
