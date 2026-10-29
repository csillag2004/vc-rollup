// Concrete syntax (thesis Table "concrete syntax", plus ->, Sig, SameHolder):
//   formula := quant | impl
//   quant   := (forall|∀|exists|∃) VAR (in|∈) DOMAIN '.' formula
//            | (atleast|atmost) NAT VAR (in|∈) DOMAIN '.' formula
//   impl    := or ( (->|→) impl )?
//   or      := and ( (|| | '|' | ∨ | or) and )*
//   and     := unary ( (&& | & | ∧ | and) unary )*
//   unary   := (!|¬|not) unary | quant | atom | '(' formula ')' | true | false
//   atom    := NAME '(' arg (',' arg)* ')'
//   DOMAIN  := NAME | Presented | Issued | Issued '[' NAME ']'
// A quantifier body extends as far right as possible; negation binds tightest, then ∧, ∨, →.
import { type Formula, type Domain, type AtomName, ARITY } from './ast.ts';

type Tok = { k: 'name' | 'num' | 'str' | 'sym'; v: string; pos: number };

const SYMS = ['->', '→', '&&', '||', '&', '|', '!', '¬', '∧', '∨', '∀', '∃', '∈', '(', ')', ',', '.', '[', ']'];

export class ParseError extends Error {
  pos: number;
  constructor(msg: string, pos: number) { super(`${msg} at ${pos}`); this.pos = pos; }
}

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (/\s/.test(c)) { i++; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i++; continue; }
    const sym = SYMS.find((s) => src.startsWith(s, i));
    if (sym) { out.push({ k: 'sym', v: sym, pos: i }); i += sym.length; continue; }
    if (c === '"') {
      let j = i + 1, s = '';
      while (j < src.length && src[j] !== '"') { if (src[j] === '\\') j++; s += src[j]; j++; }
      if (j >= src.length) throw new ParseError('unterminated string', i);
      out.push({ k: 'str', v: s, pos: i }); i = j + 1; continue;
    }
    const m = /^[0-9]+/.exec(src.slice(i));
    if (m) { out.push({ k: 'num', v: m[0], pos: i }); i += m[0].length; continue; }
    const n = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i));
    if (n) { out.push({ k: 'name', v: n[0], pos: i }); i += n[0].length; continue; }
    throw new ParseError(`unexpected '${c}'`, i);
  }
  return out;
}

export function parse(src: string): Formula {
  const toks = lex(src);
  let p = 0;
  const peek = (): Tok | undefined => toks[p];
  const at = (...vs: string[]): boolean => { const t = peek(); return !!t && (t.k === 'sym' || t.k === 'name') && vs.includes(t.v); };
  const eat = (...vs: string[]): Tok => {
    const t = peek();
    if (!t || !vs.includes(t.v)) throw new ParseError(`expected ${vs.join(' or ')}`, t?.pos ?? src.length);
    p++; return t;
  };
  const name = (): string => {
    const t = peek();
    if (!t || t.k !== 'name') throw new ParseError('expected a name', t?.pos ?? src.length);
    p++; return t.v;
  };

  const formula = (): Formula => (at('forall', '∀', 'exists', '∃', 'atleast', 'atmost') ? quant() : impl());

  const domain = (): Domain => {
    const n = name();
    if (n === 'Presented') return { kind: 'presented' };
    if (n === 'Issued') {
      if (at('[')) { eat('['); const r = name(); eat(']'); return { kind: 'issued', name: r }; }
      return { kind: 'issued', name: 'Issued' };
    }
    return { kind: 'group', name: n };
  };

  const quant = (): Formula => {
    const t = eat('forall', '∀', 'exists', '∃', 'atleast', 'atmost');
    const q = t.v === '∀' ? 'forall' : t.v === '∃' ? 'exists' : (t.v as 'forall' | 'exists' | 'atleast' | 'atmost');
    let k = 0;
    if (q === 'atleast' || q === 'atmost') {
      const n = peek();
      if (!n || n.k !== 'num') throw new ParseError('expected a number', n?.pos ?? src.length);
      p++; k = Number(n.v);
    }
    const v = name();
    eat('in', '∈');
    const dom = domain();
    eat('.');
    return { t: 'quant', q, k, v, dom, body: formula() };
  };

  const impl = (): Formula => {
    const a = or();
    if (at('->', '→')) { p++; return { t: 'implies', a, b: at('forall', '∀', 'exists', '∃', 'atleast', 'atmost') ? quant() : impl() }; }
    return a;
  };
  const or = (): Formula => {
    const fs = [and()];
    while (at('|', '||', '∨', 'or')) { p++; fs.push(and()); }
    return fs.length === 1 ? fs[0]! : { t: 'or', fs };
  };
  const and = (): Formula => {
    const fs = [unary()];
    while (at('&', '&&', '∧', 'and')) { p++; fs.push(unary()); }
    return fs.length === 1 ? fs[0]! : { t: 'and', fs };
  };
  const unary = (): Formula => {
    if (at('!', '¬', 'not')) { p++; return { t: 'not', f: unary() }; }
    if (at('forall', '∀', 'exists', '∃', 'atleast', 'atmost')) return quant();
    if (at('(')) { p++; const f = formula(); eat(')'); return f; }
    if (at('true')) { p++; return { t: 'const', v: true }; }
    if (at('false')) { p++; return { t: 'const', v: false }; }
    const t = peek();
    const n = name();
    if (!(n in ARITY)) throw new ParseError(`unknown atom ${n}`, t!.pos);
    eat('(');
    const args: string[] = [];
    do {
      const a = peek();
      if (!a || (a.k !== 'name' && a.k !== 'str')) throw new ParseError('expected an argument', a?.pos ?? src.length);
      p++; args.push(a.v);
    } while (at(',') && (p++, true));
    eat(')');
    if (args.length !== ARITY[n as AtomName]) throw new ParseError(`${n} takes ${ARITY[n as AtomName]} argument(s)`, t!.pos);
    return { t: 'atom', name: n as AtomName, args };
  };

  const f = formula();
  if (p !== toks.length) throw new ParseError('trailing input', toks[p]!.pos);
  return f;
}
