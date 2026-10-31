// Machine-readable evidence for the reduced, trusted-updater implementation.
// scripts/run.mjs supplies an isolated Prague chain and owns its lifetime.
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { runClassification, classificationTable } from './classify-exhaustive.ts';
import { runBench, benchTable } from './bench.ts';
import { runGas, gasTable } from './gas.ts';
import { runFlatReservation } from './flat-reservation.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const mode = process.argv[2] ?? 'reproduce';
const smoke = process.argv.includes('--smoke');
assert(['evaluate', 'benchmark', 'robustness', 'reproduce', 'demo'].includes(mode), `unknown mode: ${mode}`);
assert(process.env.RPC, 'RPC must identify the isolated local chain (use just reproduce)');
const out = path.resolve(process.env.OUT ?? path.join(root, 'out'));
fs.mkdirSync(out, { recursive: true });
const start = Date.now();
const outputs: string[] = [];
const report: string[] = ['# Local artifact results', '',
  `Mode: ${mode}${smoke ? ' (smoke)' : ' (full)'}. Generated ${new Date().toISOString()}.`, '',
  'Scope: hidden issuance, trusted issuer/updater, off-chain proof verification and on-chain compare-and-swap.',
  'These runs do not establish security against a malicious issuer or on-chain guard truth.', ''];

function write(name: string, text: string) {
  fs.writeFileSync(path.join(out, name), text.replaceAll(root, '<repo>'));
  outputs.push(name);
}
function csv(name: string, columns: string[], rows: unknown[][]) {
  const cell = (x: unknown) => `"${String(x ?? '').replaceAll('"', '""')}"`;
  write(name, [columns, ...rows].map(r => r.map(cell).join(',')).join('\n') + '\n');
}
function command(exe: string, args: string[]): string {
  return execFileSync(exe, args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024, timeout: 600_000 });
}
function optional(exe: string, args: string[]): string | null {
  try { return command(exe, args).trim(); } catch { return null; }
}

async function evaluate() {
  console.log('Checking classification over every comparable pair of bounded states.');
  const classification = runClassification(smoke ? 100 : 3000);
  for (const model of classification) for (const row of model.rows) {
    assert.equal(row.violations, 0, `${model.model}: ${row.verdict} classification violation`);
  }
  csv('classification.csv', ['model', 'class', 'formulas', 'violations', 'conservative_classifications'],
    classification.flatMap(m => m.rows.map(r => [m.model, r.verdict, r.formulas, r.violations, r.gap])));
  const flat = await runFlatReservation(process.env.RPC);
  const cases: [string, boolean, string][] = [
    ['naive_double_booking', flat.naiveDoubleBooking, 'two revoked group members'],
    ['atomic_group_cas', flat.casRejected === 'StaleGroupVersion', String(flat.casRejected)],
    ['stable_loser_proof', flat.loserProofValid, 'proof verifies'],
    ['stable_loser_proof_after_updates', flat.loserProofStillValidLater, 'proof stays valid and fresh'],
    ['hidden_member_credential', flat.holderReservationProof, 'signature and revoked status verify'],
  ];
  const bddLog = execFileSync('npm', ['run', 'bdd', '--', '--format', `json:${path.join(out, 'bdd.json')}`, '--format', 'progress'],
    { cwd: path.join(root, 'offchain'), env: { ...process.env, TARGET: 'anvil' }, encoding: 'utf8', timeout: 600_000, maxBuffer: 16 * 1024 * 1024 });
  write('bdd.log', bddLog);
  outputs.push('bdd.json');
  const features = JSON.parse(fs.readFileSync(path.join(out, 'bdd.json'), 'utf8')) as
    { elements: { name: string; steps: { result: { status: string } }[] }[] }[];
  for (const feature of features) for (const scenario of feature.elements) {
    assert(scenario.steps.length > 0, `empty scenario: ${scenario.name}`);
    cases.push([`bdd: ${scenario.name}`, scenario.steps.every(s => s.result.status === 'passed'), `${scenario.steps.length} steps`]);
  }
  csv('correctness.csv', ['case', 'passed', 'observed'], cases);
  for (const [name, passed] of cases) assert(passed, `${name} failed`);
  write('reservation.json', JSON.stringify(flat, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2) + '\n');
  report.push('## Correctness', '', ...cases.map(([name, ok, result]) => `- ${name}: ${ok ? 'PASS' : 'FAIL'} (${result}).`),
    '', '## Bounded classification', '', classificationTable(classification), '',
    'Formulas are sampled with seed 2026; all comparable state pairs over four IDs are enumerated for each formula.',
    'This is bounded evidence, not a proof of general classifier soundness.', '');
}

async function benchmark() {
  console.log('Measuring proof generation, verification, gas and transaction calldata.');
  const bench = await runBench(smoke);
  csv('scalability.csv', ['case', 'rule', 'sample', 'prove_ms', 'verify_ms', 'proof_element_bytes'],
    bench.flatMap(r => r.proveSamplesMs.map((t, i) => [r.case, r.rule, i + 1, t, r.verifySamplesMs[i], r.proofSamplesBytes[i]])));
  const gas = await runGas(process.env.RPC, smoke);
  csv('gas.csv', ['operation', 'detail', 'run', 'transaction', 'gas', 'calldata_bytes'],
    gas.flatMap((r, i) => r.gas.map((g, j) => [r.operation, r.detail, i + 1, j + 1, g, r.calldataBytes[j]])));
  report.push('## Off-chain proof cost', '', benchTable(bench), '',
    'Each case has one warm-up and three measured samples. CSV retains individual samples; table reports arithmetic means.',
    'Proof sizes count encoded group elements and scalars, excluding JSON framing. Crypto randomness is not seeded; timings and some proof lengths vary.', '',
    '## EVM cost', '', gasTable(gas), '',
    'Gas rows record actual receipts on Prague. Setup rows may contain several transactions; the summary sums each operation.',
    'Calldata bytes are measured from transaction input, including the function selector; they are not L1 data fees.', '');
}

function robustness() {
  console.log('Running contract rejection cases and actor guard regressions.');
  const names = ['test_issueWrongSchnorrReverts', 'test_issueWrongStepReverts', 'test_revokeWrongStepReverts',
    'test_revokeInconsistentRtildeReverts', 'test_revokeWrongWIRReverts', 'test_revokeStaleValuesReverts',
    'test_revokeTwiceReverts', 'test_revokeOutOfFieldReverts', 'test_createGroupWrongWitnessReverts',
    'test_createGroupUnsortedReverts', 'test_createGroupTooLargeReverts', 'test_policyCasModeTooWeakReverts',
    'test_flatReservationCas', 'test_groupCasIgnoresOutsideRevocation', 'test_globalCasRejectsAnyUpdate',
    'test_stableGuardNeedsNoComparison', 'test_wrongPolicyReverts'];
  const raw = command('forge', ['test', '--use', './tools/solc', '--match-contract', 'StateRegistryTest',
    '--match-test', `^(${names.join('|')})(\\(.*\\))?$`, '--json']);
  write('robustness-forge.json', raw);
  const parsed = JSON.parse(raw) as Record<string, { test_results: Record<string, { status: string; reason: string | null }> }>;
  const rows = Object.values(parsed).flatMap(s => Object.entries(s.test_results).map(([name, r]) => [name, r.status, r.reason ?? '']));
  assert.equal(rows.length, names.length, 'a required robustness case was not executed');
  for (const [name, status] of rows) assert.equal(status, 'Success', name);
  const integration = command(process.execPath, ['--test', 'offchain/test/guards.integration.ts']);
  write('guard-integration.tap', integration);
  // Node's test runner exits nonzero on any failed test. Its log is retained alongside the CSV.
  rows.push(['actor_guard_integration', 'Success', 'see guard-integration.tap']);
  csv('robustness.csv', ['case', 'status', 'detail'], rows);
  report.push('## Robustness', '', `${names.length} required Solidity rejection/freshness cases passed; actor guard integration passed.`,
    'See robustness.csv and guard-integration.tap for individual cases. These are functional rejection tests, not a denial-of-service study.', '');
}

let failed: string | undefined;
try {
  if (mode === 'evaluate' || mode === 'reproduce') await evaluate();
  if (mode === 'benchmark' || mode === 'reproduce') await benchmark();
  if (mode === 'robustness' || mode === 'reproduce') robustness();
  if (mode === 'demo') {
    const r = await runFlatReservation(process.env.RPC);
    assert(r.naiveDoubleBooking && r.casRejected === 'StaleGroupVersion' && r.loserProofStillValidLater && r.holderReservationProof);
    console.log('PASS: naive double booking reproduced; atomic CAS rejected the loser; holder proofs verified.');
  }
} catch (e) {
  failed = e instanceof Error ? e.message : String(e);
  throw e;
} finally {
  report.push('## Provenance', '', `See ${mode}-provenance.json for revision, tool versions, hardware, parameters and hashes of outputs.`,
    'The paper evaluation chapter is not yet populated; no paper table numbers or publication DOI are assigned by this run.', '');
  write(`${mode}-report.md`, report.join('\n'));
  if (mode === 'reproduce') write('report.md', report.join('\n'));
  const provenance = {
    schemaVersion: 1, mode, smoke, network: { target: 'anvil', chainId: 31337 }, success: !failed, error: failed ?? null,
    startedAt: new Date(start).toISOString(), finishedAt: new Date().toISOString(), elapsedSeconds: (Date.now() - start) / 1000,
    revision: optional('git', ['rev-parse', 'HEAD']) ?? process.env.ARTIFACT_REVISION ?? null,
    dirty: optional('git', ['status', '--porcelain']),
    platform: { os: os.platform(), release: os.release(), architecture: os.arch(), cpu: os.cpus()[0]?.model,
      logicalCpus: os.cpus().length, totalMemoryBytes: os.totalmem() },
    tools: { node: process.version, forge: optional('forge', ['--version']), anvil: optional('anvil', ['--version']),
      solc: optional('./tools/solc', ['--version']) },
    parameters: { hardfork: 'prague', classificationSeed: 2026, formulasPerModel: smoke ? 100 : 3000,
      universeSize: 4, maxFormulaDepth: 4, proofWarmups: 1, proofSamples: 3, groupSizes: smoke ? [4] : [4, 16, 64],
      cryptoRandomness: 'OS CSPRNG; fresh keys, IDs and proof blinding each run' },
    sha256: Object.fromEntries(outputs.map(name => [name, createHash('sha256').update(fs.readFileSync(path.join(out, name))).digest('hex')])),
  };
  const json = JSON.stringify(provenance, null, 2) + '\n';
  fs.writeFileSync(path.join(out, `${mode}-provenance.json`), json);
  if (mode === 'reproduce' || !fs.existsSync(path.join(out, 'provenance.json'))) {
    fs.writeFileSync(path.join(out, 'provenance.json'), json);
  }
  console.log(`${failed ? 'FAILED' : 'Completed'} ${mode}; evidence in ${out}`);
}
