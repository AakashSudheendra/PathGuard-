import { readdir, readFile } from "node:fs/promises";
import { extname, relative, resolve } from "node:path";
import ts from "typescript";

export interface SourceEvidence {
  packageName: string;
  file: string;
  line: number;
  evidenceType: "static-import" | "static-call-reference";
  importedSymbol?: string;
  expression?: string;
  reachabilityStatus: "not-proven";
}
const SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);
const IGNORED_DIRECTORIES = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next"]);

function packageFromSpecifier(specifier: string): string | undefined {
  if (specifier.startsWith(".") || specifier.startsWith("/") || specifier.startsWith("#") || specifier.startsWith("node:")) return undefined;
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? (parts.length >= 2 ? `${parts[0]}/${parts[1]}` : undefined) : parts[0];
}
async function collectSourceFiles(current: string, results: string[]): Promise<void> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!IGNORED_DIRECTORIES.has(entry.name)) await collectSourceFiles(resolve(current, entry.name), results);
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(extname(entry.name))) {
      results.push(resolve(current, entry.name));
    }
  }
}
export async function analyzeSourceUsage(projectRoot: string, installedPackages?: Set<string>): Promise<SourceEvidence[]> {
  const root = resolve(projectRoot);
  const files: string[] = [];
  await collectSourceFiles(root, files);
  const evidence = new Map<string, SourceEvidence>();

  for (const file of files) {
    let text: string;
    try { text = (await readFile(file, "utf8")).replace(/^\uFEFF/, ""); } catch { continue; }
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true,
      /\.[jt]sx$/.test(file) ? ts.ScriptKind.TSX :
      /\.(?:js|mjs|cjs)$/.test(file) ? ts.ScriptKind.JS : ts.ScriptKind.TS);
    const bindings = new Map<string, { packageName: string; importedSymbol: string }>();

    function addImport(packageName: string, node: ts.Node, symbol?: string): void {
      if (installedPackages && !installedPackages.has(packageName)) return;
      const position = source.getLineAndCharacterOfPosition(node.getStart(source));
      const item: SourceEvidence = {
        packageName, file: relative(root, file).replace(/\\/g, "/"), line: position.line + 1,
        evidenceType: "static-import", ...(symbol && { importedSymbol: symbol }), reachabilityStatus: "not-proven"
      };
      evidence.set(`${item.file}:${item.line}:${packageName}:import:${symbol ?? ""}`, item);
    }
    function visitImports(node: ts.Node): void {
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        const packageName = packageFromSpecifier(node.moduleSpecifier.text);
        if (packageName) {
          addImport(packageName, node);
          const clause = node.importClause;
          if (clause?.name) bindings.set(clause.name.text, { packageName, importedSymbol: "default" });
          const named = clause?.namedBindings;
          if (named && ts.isNamespaceImport(named)) bindings.set(named.name.text, { packageName, importedSymbol: "*" });
          else if (named && ts.isNamedImports(named)) {
            for (const element of named.elements) bindings.set(element.name.text, {
              packageName, importedSymbol: (element.propertyName ?? element.name).text
            });
          }
        }
      }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer &&
          ts.isCallExpression(node.initializer) && ts.isIdentifier(node.initializer.expression) &&
          node.initializer.expression.text === "require" && node.initializer.arguments.length === 1) {
        const arg = node.initializer.arguments[0];
        if (arg && ts.isStringLiteral(arg)) {
          const packageName = packageFromSpecifier(arg.text);
          if (packageName) {
            bindings.set(node.name.text, { packageName, importedSymbol: "*" });
            addImport(packageName, node, "*");
          }
        }
      }
      ts.forEachChild(node, visitImports);
    }
    visitImports(source);

    function visitCalls(node: ts.Node): void {
      if (ts.isCallExpression(node)) {
        let localName: string | undefined;
        let symbol: string | undefined;
        if (ts.isIdentifier(node.expression)) localName = node.expression.text;
        else if (ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression)) {
          localName = node.expression.expression.text;
          symbol = node.expression.name.text;
        }
        const binding = localName ? bindings.get(localName) : undefined;
        if (binding && (
          binding.importedSymbol === "*" ||
          binding.importedSymbol === "default" ||
          (symbol === undefined && binding.importedSymbol !== "*") ||
          binding.importedSymbol === symbol
        )) {
          const position = source.getLineAndCharacterOfPosition(node.expression.getStart(source));
          const expression = node.expression.getText(source);
          const item: SourceEvidence = {
            packageName: binding.packageName, file: relative(root, file).replace(/\\/g, "/"),
            line: position.line + 1, evidenceType: "static-call-reference",
            importedSymbol: symbol ?? binding.importedSymbol, expression, reachabilityStatus: "not-proven"
          };
          evidence.set(`${item.file}:${item.line}:${item.packageName}:call:${expression}`, item);
        }
      }
      ts.forEachChild(node, visitCalls);
    }
    visitCalls(source);
  }
  return [...evidence.values()].sort((a,b) => a.packageName.localeCompare(b.packageName) || a.file.localeCompare(b.file) || a.line-b.line);
}
export function summarizeSourceEvidence(evidence: SourceEvidence[]) {
  return {
    filesWithEvidence: new Set(evidence.map((x) => x.file)).size,
    packagesWithEvidence: new Set(evidence.map((x) => x.packageName)).size,
    importEvidenceCount: evidence.filter((x) => x.evidenceType === "static-import").length,
    callReferenceCount: evidence.filter((x) => x.evidenceType === "static-call-reference").length,
    reachabilityProvenCount: evidence.filter((x) => x.reachabilityStatus !== "not-proven").length
  };
}
