// Exhaustive semantic check of the classification: random closed formulas, every pair Σ ⊑ Σ'
// of states over a universe of 4 IDs, in the system model and in the thesis' general model.
import { runExhaustive, type ExhaustiveRow } from '../src/ql/exhaustive.ts';

export function runClassification(formulas = 3000): { model: string; rows: ExhaustiveRow[] }[] {
  const base = {
    universe: [1n, 2n, 3n, 4n],
    groups: new Map([['S', [1n, 2n, 3n]], ['T', [2n, 4n]]]),
    presented: [1n, 4n],
    formulas, maxDepth: 4, seed: 2026,
  };
  return [
    { model: 'system model (domains hold issued IDs)', rows: runExhaustive({ ...base, domainsIssued: true }) },
    { model: 'general model (groups of arbitrary IDs)', rows: runExhaustive({ ...base, domainsIssued: false }) },
  ];
}

export function classificationTable(res: ReturnType<typeof runClassification>): string {
  const lines = ['| Model | Verdict | Formulas | Violations | Volatile but semantically (co-)stable |', '|---|---|---:|---:|---:|'];
  for (const { model, rows } of res) for (const r of rows) lines.push(`| ${model} | ${r.verdict} | ${r.formulas} | ${r.violations} | ${r.verdict === 'volatile' ? r.gap : '–'} |`);
  return lines.join('\n');
}

if (import.meta.url === `file://${process.argv[1]}`) console.log(classificationTable(runClassification()));
