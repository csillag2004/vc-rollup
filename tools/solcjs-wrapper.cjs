// Native-solc command-line shim over the solc-js Emscripten build (npm "solc", soljson.js), for
// machines where forge cannot download a native compiler. Supports what forge uses:
// --version and --standard-json (input on stdin, all sources inlined by forge).
const fs = require('fs');
const path = require('path');
const soljson = require(path.join(__dirname, '..', 'offchain', 'node_modules', 'solc', 'soljson.js'));

const version = soljson.cwrap('solidity_version', 'string', [])();
const args = process.argv.slice(2);
if (args.includes('--version')) {
  process.stdout.write(`solc, the solidity compiler commandline interface\nVersion: ${version.replace('.Emscripten.clang', '')}.Linux.g++\n`);
  process.exit(0);
}
if (!args.includes('--standard-json')) {
  process.stderr.write('only --version and --standard-json are supported\n');
  process.exit(1);
}
const compile = soljson.cwrap('solidity_compile', 'string', ['string', 'number', 'number']);
process.stdout.write(compile(fs.readFileSync(0, 'utf8'), 0, 0));
