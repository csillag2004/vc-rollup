// Compatibility entry point: use the same isolated-chain reproduction as the artifact recipes.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
execFileSync(process.execPath, [fileURLToPath(new URL('../../scripts/run.mjs', import.meta.url)), 'reproduce', ...process.argv.slice(2)], { stdio: 'inherit' });
