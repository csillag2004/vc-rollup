// Is a presentation, bound to registry versions, still good against the current ledger?
// (thesis Def. fresh guard: stable → any authenticated earlier state; group CAS → the group
// versions are unchanged; otherwise → the bound versions are the current ones.)
import type { FormulaClass, CasMode } from './logic.ts';
import type { PublicContext, Presentation } from './compile.ts';
import { currentVersion, groupVersionAt } from '../registry/history.ts';

export interface Freshness { fresh: boolean; reason?: string }

export function checkFreshness(p: Presentation, cls: FormulaClass, cas: CasMode, ctx: PublicContext): Freshness {
  for (const [id, v] of Object.entries(p.versions)) {
    const h = ctx.registries.get(id);
    if (!h || v < 0 || v > currentVersion(h)) return { fresh: false, reason: `version ${v} of ${id} is not ledger history` };
  }
  if (cls === 'stable' || cls === 'state-independent' || cas === 'none') return { fresh: true };
  if (cas === 'group') {
    for (const [name, b] of ctx.bindings) {
      if (b.kind !== 'group') continue;
      const h = ctx.registries.get(b.registryId)!;
      const then = groupVersionAt(h, b.members, p.versions[b.registryId]!);
      const now = groupVersionAt(h, b.members, currentVersion(h));
      if (then !== now) return { fresh: false, reason: `group ${name} moved from version ${then} to ${now}` };
    }
    return { fresh: true };
  }
  for (const [id, v] of Object.entries(p.versions)) {
    const now = currentVersion(ctx.registries.get(id)!);
    if (v !== now) return { fresh: false, reason: `registry ${id} moved from version ${v} to ${now}` };
  }
  return { fresh: true };
}
