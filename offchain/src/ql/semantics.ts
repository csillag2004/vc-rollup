// Truth of closed formulas in a registry state (thesis Notation "truth of formulas").
import type { Formula, Domain } from './ast.ts';

export interface State { iss: Set<bigint>; rev: Set<bigint> }

export interface Env {
  /** registry state per Issued-domain name (one registry in the simple case: key 'Issued') */
  states: Map<string, State>;
  /** the state used for atoms; in the single-registry model the one and only state */
  state: State;
  groups: Map<string, bigint[]>;
  presented: bigint[];
  sig?: (y: bigint, name: string) => boolean;
  sameHolder?: (a: bigint, b: bigint) => boolean;
}

export function domainSet(d: Domain, env: Env): bigint[] {
  if (d.kind === 'group') {
    const g = env.groups.get(d.name);
    if (!g) throw new Error(`unknown group ${d.name}`);
    return g;
  }
  if (d.kind === 'presented') return env.presented;
  const s = env.states.get(d.name) ?? env.state;
  return [...s.iss];
}

export function holds(f: Formula, env: Env, asg: Map<string, bigint> = new Map()): boolean {
  switch (f.t) {
    case 'const': return f.v;
    case 'atom': {
      const y = asg.get(f.args[0]!)!;
      switch (f.name) {
        case 'Revoked': return env.state.rev.has(y);
        case 'NotRevoked': return !env.state.rev.has(y);
        case 'Issued': return env.state.iss.has(y);
        case 'NotIssued': return !env.state.iss.has(y);
        case 'Active': return env.state.iss.has(y) && !env.state.rev.has(y);
        case 'Sig': return env.sig ? env.sig(y, f.args[1]!) : true;
        case 'SameHolder': return env.sameHolder ? env.sameHolder(y, asg.get(f.args[1]!)!) : y === asg.get(f.args[1]!);
      }
      return false;
    }
    case 'not': return !holds(f.f, env, asg);
    case 'and': return f.fs.every((g) => holds(g, env, asg));
    case 'or': return f.fs.some((g) => holds(g, env, asg));
    case 'implies': return !holds(f.a, env, asg) || holds(f.b, env, asg);
    case 'quant': {
      const dom = domainSet(f.dom, env);
      let count = 0;
      for (const y of dom) if (holds(f.body, env, new Map([...asg, [f.v, y]]))) count++;
      switch (f.q) {
        case 'forall': return count === dom.length;
        case 'exists': return count >= 1;
        case 'atleast': return count >= f.k;
        case 'atmost': return count <= f.k;
      }
    }
  }
}
