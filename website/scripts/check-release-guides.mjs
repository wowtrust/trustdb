import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const websiteRoot = fileURLToPath(new URL("..", import.meta.url));
const sourceRoot = join(websiteRoot, "src");
const sourceBuildStart = "export function SourceBuildPage";
const sourceBuildEnd = "export function MissingDocsPage";
const forbidden = [
  ["git clone", /\bgit clone\b/i],
  ["go build", /\bgo build\b/i],
  ["docker build", /\bdocker build\b/i],
  ["wails build", /\bwails build\b/i],
  ["local Go module replace", /go mod edit\s+-replace|replace=github\.com\/wowtrust\/trustdb/i],
  ["source-tree config path", /configs\/(?:docker|production)\.yaml/i],
  ["floating local image", /\btrustdb:main\b/i],
];

function filesUnder(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return filesUnder(path);
    return /\.(?:js|jsx|mjs)$/.test(entry.name) ? [path] : [];
  });
}

const violations = [];
for (const file of filesUnder(sourceRoot)) {
  let content = readFileSync(file, "utf8");
  if (file.endsWith("pages/DocsPages.jsx")) {
    const start = content.indexOf(sourceBuildStart);
    const end = content.indexOf(sourceBuildEnd);
    if (start < 0 || end <= start) {
      throw new Error("Unable to isolate the dedicated SourceBuildPage");
    }
    content = `${content.slice(0, start)}${content.slice(end)}`;
  }
  for (const [label, pattern] of forbidden) {
    if (pattern.test(content)) violations.push(`${relative(websiteRoot, file)}: ${label}`);
  }
}

if (violations.length > 0) {
  console.error("Release-first documentation policy violations:");
  for (const violation of violations) console.error(`- ${violation}`);
  process.exit(1);
}

console.log("Release-first documentation policy passed.");
