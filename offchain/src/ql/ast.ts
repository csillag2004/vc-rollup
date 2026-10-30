// Abstract syntax of the query language (thesis Def. conditions, domains, quantifiers, formulas).

export type RegAtomName = 'Revoked' | 'NotRevoked' | 'Issued' | 'NotIssued';
export type CredAtomName = 'Sig' | 'SameHolder';
export type AtomName = RegAtomName | CredAtomName | 'Active';
export type QuantKind = 'forall' | 'exists' | 'atleast' | 'atmost';

/** a group by name, the holder's presented credentials, or a registry's issued set (by binding name) */
export type Domain =
  | { kind: 'group'; name: string }
  | { kind: 'presented' }
  | { kind: 'issued'; name: string };

export type Formula =
  | { t: 'const'; v: boolean }
  | { t: 'atom'; name: AtomName; args: string[] }
  | { t: 'not'; f: Formula }
  | { t: 'and'; fs: Formula[] }
  | { t: 'or'; fs: Formula[] }
  | { t: 'implies'; a: Formula; b: Formula }
  | { t: 'quant'; q: QuantKind; k: number; v: string; dom: Domain; body: Formula };

export const REG_ATOMS: RegAtomName[] = ['Revoked', 'NotRevoked', 'Issued', 'NotIssued'];
export const DUAL: Record<RegAtomName, RegAtomName> = {
  Revoked: 'NotRevoked', NotRevoked: 'Revoked', Issued: 'NotIssued', NotIssued: 'Issued',
};
export const ARITY: Record<AtomName, number> = {
  Revoked: 1, NotRevoked: 1, Issued: 1, NotIssued: 1, Active: 1, Sig: 2, SameHolder: 2,
};

export const isRegAtom = (n: string): n is RegAtomName => (REG_ATOMS as string[]).includes(n);

export function domainKey(d: Domain): string {
  return d.kind === 'group' ? `group:${d.name}` : d.kind === 'issued' ? `issued:${d.name}` : 'presented';
}

export function pretty(f: Formula): string {
  switch (f.t) {
    case 'const': return f.v ? 'true' : 'false';
    case 'atom': return `${f.name}(${f.args.map((a, i) => (f.name === 'Sig' && i === 1 ? JSON.stringify(a) : a)).join(', ')})`;
    case 'not': return `!${wrap(f.f)}`;
    case 'and': return f.fs.map(wrap).join(' & ');
    case 'or': return f.fs.map(wrap).join(' | ');
    case 'implies': return `${wrap(f.a)} -> ${wrap(f.b)}`;
    case 'quant': {
      const q = f.q === 'atleast' || f.q === 'atmost' ? `${f.q} ${f.k}` : f.q;
      const d = f.dom.kind === 'group' ? f.dom.name : f.dom.kind === 'issued' ? (f.dom.name === 'Issued' ? 'Issued' : `Issued[${f.dom.name}]`) : 'Presented';
      return `${q} ${f.v} in ${d}. ${pretty(f.body)}`;
    }
  }
}

const wrap = (f: Formula): string => (f.t === 'atom' || f.t === 'const' || f.t === 'not' ? pretty(f) : `(${pretty(f)})`);

/** domains of all quantifiers (thesis Def. domains of a formula) */
export function domainsOf(f: Formula, out: Domain[] = []): Domain[] {
  switch (f.t) {
    case 'not': domainsOf(f.f, out); break;
    case 'and': case 'or': f.fs.forEach((g) => domainsOf(g, out)); break;
    case 'implies': domainsOf(f.a, out); domainsOf(f.b, out); break;
    case 'quant': out.push(f.dom); domainsOf(f.body, out); break;
  }
  return out;
}

export function freeVars(f: Formula, bound: Set<string> = new Set(), out: Set<string> = new Set()): Set<string> {
  switch (f.t) {
    case 'atom': f.args.forEach((a, i) => { if (!(f.name === 'Sig' && i === 1) && !bound.has(a)) out.add(a); }); break;
    case 'not': freeVars(f.f, bound, out); break;
    case 'and': case 'or': f.fs.forEach((g) => freeVars(g, bound, out)); break;
    case 'implies': freeVars(f.a, bound, out); freeVars(f.b, bound, out); break;
    case 'quant': freeVars(f.body, new Set([...bound, f.v]), out); break;
  }
  return out;
}
