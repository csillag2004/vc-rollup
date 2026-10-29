// Native-solc command-line shim over solc-js (npm "solc"), for machines where forge cannot
// download a native compiler. Supports what forge uses: --version and --standard-json (stdin).
const fs = require('fs');
const path = require('path');
const solc = require(path.join(__dirname, '..', 'offchain', 'node_modules', 'solc'));

const args = process.argv.slice(2);
if (args.includes('--version')) {
  const v = solc.version().replace('.Emscripten.clang', '');
  process.stdout.write(`solc, the solidity compiler commandline interface\nVersion: ${v}.Linux.g++\n`);
  process.exit(0);
}
if (!args.includes('--standard-json')) {
  process.stderr.write('only --version and --standard-json are supported\n');
  process.exit(1);
}
const basePath = (() => { const i = args.indexOf('--base-path'); return i >= 0 ? args[i + 1] : process.cwd(); })();
const includes = [];
args.forEach((a, i) => { if (a === '--include-path') includes.push(args[i + 1]); });
const input = fs.readFileSync(0, 'utf8');
const findImports = (p) => {
  for (const root of [basePath, ...includes, process.cwd()]) {
    const full = path.resolve(root, p);
    if (fs.existsSync(full)) return { contents: fs.readFileSync(full, 'utf8') };
  }
  return { error: `not found: ${p}` };
};
process.stdout.write(solc.compile(input, { import: findImports }));
