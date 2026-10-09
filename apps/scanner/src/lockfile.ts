import { readFile } from "node:fs/promises";

export interface LockedDependency {
  name: string;
  version: string;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function readNpmLockfile(path: string): Promise<LockedDependency[]> {
  const raw = (await readFile(path, "utf8")).replace(/^\uFEFF/, "");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Invalid JSON in lockfile "${path}": ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isObject(parsed)) throw new Error("package-lock.json must contain a JSON object.");

  const result = new Map<string, LockedDependency>();
  const lockVersion = Number(parsed.lockfileVersion ?? 1);

  if (lockVersion >= 2 && isObject(parsed.packages)) {
    for (const [location, info] of Object.entries(parsed.packages)) {
      if (!location || !isObject(info) || typeof info.version !== "string") continue;
      const name = typeof info.name === "string" ? info.name : nameFromNodeModulesPath(location);
      if (!name || !isInstallableVersion(info.version)) continue;
      result.set(`${name}@${info.version}`, { name, version: info.version });
    }
  } else if (isObject(parsed.dependencies)) {
    walkLegacyDependencies(parsed.dependencies, result);
  } else if (!(lockVersion >= 2 && isObject(parsed.packages))) {
    throw new Error("Unsupported package-lock.json structure: expected packages (lockfile v2/v3) or dependencies (v1).");
  }

  return [...result.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

function nameFromNodeModulesPath(location: string): string | undefined {
  const marker = "node_modules/";
  const index = location.lastIndexOf(marker);
  if (index < 0) return undefined;
  return location.slice(index + marker.length);
}

function isInstallableVersion(version: string): boolean {
  return version.length > 0 && !version.startsWith("file:") && !version.startsWith("git+") &&
    !version.startsWith("http:") && !version.startsWith("https:");
}

function walkLegacyDependencies(
  dependencies: Record<string, unknown>,
  result: Map<string, LockedDependency>
): void {
  for (const [name, entry] of Object.entries(dependencies)) {
    if (!isObject(entry)) continue;
    if (typeof entry.version === "string" && isInstallableVersion(entry.version)) {
      result.set(`${name}@${entry.version}`, { name, version: entry.version });
    }
    if (isObject(entry.dependencies)) walkLegacyDependencies(entry.dependencies, result);
  }
}
