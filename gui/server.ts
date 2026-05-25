/**
 * GUI bridge — exposes the existing Issuer/Holder/Verifier over HTTP so the
 * browser-side Credential Console can invoke them.
 *
 * Run with:   npx ts-node gui/server.ts
 * Open with:  http://localhost:3001
 *
 * This file is a thin adapter: it never reaches inside the business logic.
 * Per-credential metadata that the logic layer does not track (holder display
 * name, the attribute values the user typed for issueCredential, the
 * sign/witness/revoke flags) is held here as GUI-only state.
 */
import 'dotenv/config';
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';

import { Issuer } from '../ts-scripts/issuer';
import { Holder } from '../ts-scripts/holder';
import { Verifier } from '../ts-scripts/verifier';

// ─────────────────────────────────────────────────────────────────────
// Wire up the three actors. They auto-connect to the contracts named
// in .env when constructed.
// ─────────────────────────────────────────────────────────────────────
let issuer   = new Issuer();
let holder   = new Holder();
let verifier = new Verifier();

// GUI-only metadata. The logic layer does not track these.
type Meta = {
  attrValues: Map<string, string[]>;          // credId → attribute values typed at issuance
  holderName: Map<string, string>;             // credId → display name
  revoked:    Set<string>;
  witnessed:  Set<string>;
  signed:     Set<string>;
  proofMeta:  Map<string, { revealed: number[]; revealedMap: Record<string, string>; proofBytes: string }>;
  lastVerified: { credId: string; holderName: string; schemaId: string; revealed: number[]; revealedMap: Record<string,string>; isValid: boolean } | null;
};
const meta: Meta = {
  attrValues: new Map(),
  holderName: new Map(),
  revoked:    new Set(),
  witnessed:  new Set(),
  signed:     new Set(),
  proofMeta:  new Map(),
  lastVerified: null,
};

// Address of the wallet powering each actor — derived from the env-supplied
// private keys so the GUI can show them in the panel headers.
function deriveAddrs() {
  const pk = (k: string | undefined) => {
    if (!k) return '';
    try { return new ethers.Wallet(k).address; } catch { return ''; }
  };
  return {
    issuer:   pk(process.env.PRIVATE_KEY_ISSUER),
    holder:   pk(process.env.PRIVATE_KEY_HOLDER),
    verifier: pk(process.env.PRIVATE_KEY_VERIFIER),
  };
}
const ACTOR_ADDR = deriveAddrs();

// Shared read-only RPC for block-number polling. The actors each have their
// own provider on the same RPC; we open one more here so we don't piggy-back
// on a private field.
const RPC_URL = 'https://sepolia-rpc.scroll.io';
const provider = new ethers.JsonRpcProvider(RPC_URL);

// ─────────────────────────────────────────────────────────────────────
// State snapshot — builds the shape the design's React UI expects.
// ─────────────────────────────────────────────────────────────────────
type LogLine = { kind: 'tx' | 'ok' | 'warn' | 'info' | 'err'; actor: string; msg: string; hash?: string };

function hexOf(u?: Uint8Array | null) {
  if (!u) return null;
  return '0x' + Buffer.from(u).toString('hex');
}

async function buildState() {
  // Cast to any so we can reach contracts the logic layer holds as private.
  const ix = issuer as any;
  const hx = holder as any;
  const vx = verifier as any;

  // Accumulator
  let accValueHex: string | null = null;
  let accPkHex:    string | null = null;
  try {
    const acc = await issuer.getOnChainAccumulator();
    if (acc) accValueHex = hexOf(acc.accumulated);
    const pk  = await issuer.getPublicKey();
    if (pk)  accPkHex    = hexOf(pk.bytes);
  } catch (e) {
    // Network hiccup — leave them null; UI shows "not yet initialised".
  }

  // Schemas — fetch name/version from on-chain via the issuer's contract.
  const schemas: Record<string, any> = {};
  for (const id of issuer.getSchemaIds()) {
    try {
      const s = await ix.schemaRegistryContract.getSchema(id);
      schemas[id] = {
        id,
        name: s.name,
        version: s.version,
        attributes: Array.from(s.attributeNames as string[]),
      };
    } catch (_) {
      schemas[id] = { id, name: '?', version: '?', attributes: [] };
    }
  }

  // CredDefs — every (schema, credDef) pair we know about.
  const credDefs: Record<string, any> = {};
  for (const sid of issuer.getSchemaIds()) {
    for (const cid of issuer.getCredDefIdsForSchema(sid)) {
      credDefs[cid] = { id: cid, schemaId: sid, tag: 'default' };
    }
  }

  // Registries
  const registries: Record<string, any> = {};
  for (const sid of issuer.getSchemaIds()) {
    for (const cid of issuer.getCredDefIdsForSchema(sid)) {
      for (const rid of issuer.getRegistryIdsForCredDef(sid, cid)) {
        registries[rid] = { id: rid, credDefId: cid, schemaId: sid };
      }
    }
  }

  // Credentials
  const credentials: Record<string, any> = {};
  for (const sid of issuer.getSchemaIds()) {
    for (const cid of issuer.getCredDefIdsForSchema(sid)) {
      for (const rid of issuer.getRegistryIdsForCredDef(sid, cid)) {
        for (const credId of issuer.getCredIdsForRegistry(sid, cid, rid)) {
          let y: number | null = null;
          try { y = await issuer.findYByCredId(credId); } catch (_) {}
          credentials[credId] = {
            credId,
            registryId: rid,
            credDefId:  cid,
            schemaId:   sid,
            holderName: meta.holderName.get(credId) || '',
            attributeValues: meta.attrValues.get(credId) || [],
            y,
            status:    meta.revoked.has(credId) ? 'revoked' : 'active',
            signed:    meta.signed.has(credId),
            witnessed: meta.witnessed.has(credId),
          };
        }
      }
    }
  }

  // Holder inbox — derived from holder's credentialMap
  const holderInbox: Record<string, any> = {};
  const hMap: Map<string, any> = hx.credentialMap;
  if (hMap) {
    for (const [credId, cred] of hMap.entries()) {
      const sigHex = cred?.signature?.value ? hexOf(cred.signature.value) : null;
      holderInbox[credId] = {
        credId,
        holderName: meta.holderName.get(credId) || '',
        schemaId:   cred.schemaId,
        attributeValues: meta.attrValues.get(credId) || [],
        signature:  sigHex || '0x',
        witnessBytes: cred.private_witness ? hexOf(cred.private_witness) : null,
        epoch:      cred.epoch,
        witnessSynced: !meta.revoked.has(credId),
      };
    }
  }

  // Verifier inbox — drawn from verifier.proofinfo, decorated with our recall of which attrs were revealed.
  const proofs: any[] = [];
  const vMap: Map<string, any> = vx.proofinfo;
  if (vMap) {
    for (const [credId, p] of vMap.entries()) {
      const m = meta.proofMeta.get(credId) || { revealed: [], revealedMap: {}, proofBytes: '0x' };
      proofs.push({
        credId,
        holderName: meta.holderName.get(credId) || '',
        schemaId:   p.schemaId,
        revealed:   m.revealed,
        revealedMap: m.revealedMap,
        proofBytes: m.proofBytes,
      });
    }
  }

  let block: number | null = null;
  try { block = await provider.getBlockNumber(); } catch (_) {}

  return {
    accumulator: accValueHex ? { value: accValueHex, pubKey: accPkHex || '0x', epoch: 0 } : null,
    schemas, credDefs, registries, credentials,
    witnesses: {},                  // not surfaced separately — sidebar shows it via cred.witnessed
    holderInbox,
    verifierInbox: { proofs, lastVerified: meta.lastVerified },
    actors: ACTOR_ADDR,
    block,
    txCount: 0,                     // unused now that we show real block height
  };
}

// ─────────────────────────────────────────────────────────────────────
// Command handlers — one per design button. Each maps inputs → real call.
// ─────────────────────────────────────────────────────────────────────
type RunResult = { log: LogLine[] };

const handlers: Record<string, (v: any) => Promise<RunResult>> = {

  async initAccumulator() {
    await issuer.createAccumulator();
    return { log: [
      { kind: 'info', actor: 'issuer', msg: 'generate VB-accumulator params + keypair' },
      { kind: 'tx',   actor: 'issuer', msg: 'Accumulator.setAccumulator() / setParams() / setPublicKey() confirmed' },
      { kind: 'ok',   actor: 'issuer', msg: 'accumulator live on Scroll Sepolia' },
    ]};
  },

  async registerSchema(v) {
    if (!v.name) throw new Error('schema name is required');
    if (!v.version) throw new Error('version is required');
    const attrs = String(v.attributes || '').split(/[,\n]/g).map((s: string) => s.trim()).filter(Boolean);
    if (attrs.length === 0) throw new Error('at least one attribute is required');
    await issuer.schemaId(v.name, v.version, attrs);
    const ids = issuer.getSchemaIds();
    const id = ids[ids.length - 1] || '';
    return { log: [
      { kind: 'tx', actor: 'issuer', msg: `SchemaRegistry.registerSchema("${v.name}", "${v.version}", [${attrs.length}])` },
      { kind: 'ok', actor: 'issuer', msg: `schemaId minted ${id.slice(0, 18)}…` },
    ]};
  },

  async registerCredDef(v) {
    if (!v.schemaId) throw new Error('schema is required');
    // Tag is informational on the GUI; the logic layer hardcodes "default".
    const id = await issuer.credDefId(v.schemaId);
    return { log: [
      { kind: 'info', actor: 'issuer', msg: 'BBS+G2 keypair attribute published to the DID registry' },
      { kind: 'tx',   actor: 'issuer', msg: 'CredDefRegistry.registerCredDef() confirmed' },
      { kind: 'ok',   actor: 'issuer', msg: `credDefId minted ${String(id).slice(0, 18)}…` },
    ]};
  },

  async createRegistry(v) {
    if (!v.credDefId) throw new Error('credDef is required');
    await issuer.revocationRegistry(v.credDefId);
    return { log: [
      { kind: 'tx', actor: 'issuer', msg: 'RevocationRegistry.createRegistry() confirmed' },
      { kind: 'ok', actor: 'issuer', msg: 'registry wired to accumulator' },
    ]};
  },

  async issueCredential(v) {
    if (!v.registryId) throw new Error('registry is required');
    if (!v.credId)     throw new Error('credId is required');
    if (!v.holderName) throw new Error('holder name is required');
    // Look up the schema attached to the chosen registry so we know which
    // attribute fields the form was supposed to collect.
    const credDefId = issuer.findCredDefIdByRegistry(v.registryId);
    if (!credDefId) throw new Error('cannot resolve credDef for this registry');
    const schemaId = issuer.findSchemaIdByCredDef(credDefId);
    if (!schemaId) throw new Error('cannot resolve schema for this registry');
    const ix = issuer as any;
    const schema = await ix.schemaRegistryContract.getSchema(schemaId);
    const attrs = Array.from(schema.attributeNames as string[]);
    const attrValues = attrs.map((_, i) => String(v[`attr:${i}`] || '').trim());
    if (attrValues.some((x) => !x)) throw new Error('fill every attribute value');

    await issuer.addCredentials(v.credId, v.registryId, holder);

    meta.attrValues.set(v.credId, attrValues);
    meta.holderName.set(v.credId, v.holderName);

    return { log: [
      { kind: 'info', actor: 'issuer', msg: `assign y(${v.credId}) — random scalar member` },
      { kind: 'tx',   actor: 'issuer', msg: 'RevocationRegistry.updateRegistry(adds=[y]) confirmed' },
      { kind: 'tx',   actor: 'issuer', msg: 'Accumulator.setAccumulator(post-add) confirmed' },
      { kind: 'ok',   actor: 'issuer', msg: `credential ${v.credId} (${v.holderName}) issued` },
    ]};
  },

  async revokeCredential(v) {
    if (!v.credId) throw new Error('credential is required');
    const registryId = await issuer.findRegistryIdByCredId(v.credId);
    if (!registryId) throw new Error(`registry for ${v.credId} not found`);
    await issuer.revokeCredentials(v.credId, registryId);
    meta.revoked.add(v.credId);
    const hn = meta.holderName.get(v.credId) || '';
    return { log: [
      { kind: 'warn', actor: 'issuer', msg: `remove y(${v.credId}) from accumulator state` },
      { kind: 'tx',   actor: 'issuer', msg: 'Accumulator.setAccumulator(post-remove) confirmed' },
      { kind: 'tx',   actor: 'issuer', msg: 'RevocationRegistry.updateRegistry(removes=[y]) confirmed' },
      { kind: 'ok',   actor: 'issuer', msg: `${v.credId}${hn ? ' (' + hn + ')' : ''} revoked` },
    ]};
  },

  async createWitness(v) {
    if (!v.credId) throw new Error('credential is required');
    await issuer.createWitness(v.credId);
    meta.witnessed.add(v.credId);
    return { log: [
      { kind: 'info', actor: 'issuer', msg: `compute VBMembershipWitness for y(${v.credId})` },
      { kind: 'ok',   actor: 'issuer', msg: `witness ready for ${v.credId}` },
    ]};
  },

  async signCredential(v) {
    if (!v.credId) throw new Error('credential is required');
    const witnessPair = issuer.getWitness(v.credId);
    if (!witnessPair) throw new Error('no witness on file — run Create Witness first');
    const attrValues = meta.attrValues.get(v.credId);
    if (!attrValues) throw new Error('no attribute values on file — re-issue this credential');
    // Re-derive message_count the same way the cucumber step does:
    // messageList.length + 1 (the +1 is the trailing revocationId / K_HANDLE)
    await issuer.signCredential(v.credId, attrValues, witnessPair, attrValues.length + 1);
    meta.signed.add(v.credId);
    return { log: [
      { kind: 'info', actor: 'issuer', msg: `encode ${attrValues.length} attrs + revocationId as BBS+ message vector` },
      { kind: 'ok',   actor: 'issuer', msg: `σ and witness handed to holder` },
    ]};
  },

  async updateWitness(v) {
    if (!v.credId) throw new Error('credential is required');
    await holder.updateWitness(v.credId);
    return { log: [
      { kind: 'info', actor: 'holder', msg: 'replay AccumulatorUpdated events from lastSyncedBlock' },
      { kind: 'ok',   actor: 'holder', msg: `witness brought to head for ${v.credId}` },
    ]};
  },

  async generateProof(v) {
    if (!v.credId) throw new Error('credential is required');
    const reveals = (v.reveal || []).map((x: string) => Number(x));
    const proof = await holder.compositeProofForCredential(v.credId, reveals, verifier);
    if (!proof) throw new Error('proof generation returned null');
    // Snapshot the reveal map for the sidebar/inbox views
    const cred = (holder as any).credentialMap.get(v.credId);
    const schemaId = cred?.schemaId;
    let attrs: string[] = [];
    try {
      const ix = issuer as any;
      const s = await ix.schemaRegistryContract.getSchema(schemaId);
      attrs = Array.from(s.attributeNames as string[]);
    } catch (_) {}
    const attrValues = meta.attrValues.get(v.credId) || [];
    const revealedMap: Record<string, string> = {};
    for (const i of reveals) {
      if (attrs[i] != null) revealedMap[attrs[i]] = attrValues[i] || '';
    }
    // Surface a small chunk of the proof bytes for the inbox display.
    let proofBytes = '0x';
    try {
      const pb = (proof as any).value;
      if (pb) proofBytes = hexOf(pb) || '0x';
    } catch (_) {}
    meta.proofMeta.set(v.credId, { revealed: reveals, revealedMap, proofBytes });
    return { log: [
      { kind: 'info', actor: 'holder', msg: `Statement.bbsPlusSignatureProver(revealed={${reveals.join(', ')}})` },
      { kind: 'info', actor: 'holder', msg: 'Statement.vbAccumulatorMembership(provingKey, acc)' },
      { kind: 'ok',   actor: 'holder', msg: `CompositeProof generated and handed to verifier` },
    ]};
  },

  async verifyProof(v) {
    if (!v.credId) throw new Error('proof is required');
    const result = await verifier.buildCompositeProof(v.credId);
    const isValid = !!(result && (result as any).verified);
    const m = meta.proofMeta.get(v.credId);
    const schemaId = (verifier as any).proofinfo?.get(v.credId)?.schemaId || '';
    meta.lastVerified = {
      credId: v.credId,
      holderName: meta.holderName.get(v.credId) || '',
      schemaId,
      revealed: m?.revealed || [],
      revealedMap: m?.revealedMap || {},
      isValid,
    };
    return { log: [
      { kind: 'info', actor: 'verifier', msg: 'fetch accumulator value + pk + params from chain' },
      { kind: 'info', actor: 'verifier', msg: 'CompositeProof.verify(verifierSpec, nonce)' },
      isValid
        ? { kind: 'ok',   actor: 'verifier', msg: `proof.verified = true · claims authentic, not revoked` } as LogLine
        : { kind: 'warn', actor: 'verifier', msg: `proof.verified = false · membership failed or signature invalid` } as LogLine,
    ]};
  },
};

// ─────────────────────────────────────────────────────────────────────
// HTTP layer
// ─────────────────────────────────────────────────────────────────────
const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.jsx':  'text/babel; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
};

const PUBLIC_DIR = path.join(__dirname, 'public');

function sendJson(res: http.ServerResponse, status: number, body: any) {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': buf.length });
  res.end(buf);
}

function serveStatic(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = (req.url || '/').split('?')[0] || '/';
  const rel = (url === '/' ? '/index.html' : url).replace(/^\/+/, '');
  const abs = path.join(PUBLIC_DIR, rel);
  if (!abs.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); res.end('forbidden'); return;
  }
  fs.readFile(abs, (err, buf) => {
    if (err) { res.writeHead(404); res.end('not found'); return; }
    const mime = MIME[path.extname(abs).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime, 'Content-Length': buf.length });
    res.end(buf);
  });
}

async function readJsonBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf-8');
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = (req.url || '/').split('?')[0] || '/';
  const method = req.method || 'GET';

  // CORS: harmless on localhost but useful if the user opens the file directly.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  try {
    if (url === '/api/state' && method === 'GET') {
      const state = await buildState();
      return sendJson(res, 200, state);
    }

    if (url === '/api/reset' && method === 'POST') {
      issuer = new Issuer();
      holder = new Holder();
      verifier = new Verifier();
      meta.attrValues.clear();
      meta.holderName.clear();
      meta.revoked.clear();
      meta.witnessed.clear();
      meta.signed.clear();
      meta.proofMeta.clear();
      meta.lastVerified = null;
      const state = await buildState();
      return sendJson(res, 200, { state, log: [{ kind: 'info', actor: 'system', msg: 'GUI bridge reset — actors re-instantiated' }] });
    }

    if (url.startsWith('/api/run/') && method === 'POST') {
      const id = url.slice('/api/run/'.length);
      const handler = handlers[id];
      if (!handler) return sendJson(res, 404, { error: `unknown command: ${id}` });
      const body = await readJsonBody(req);
      console.log(`[${new Date().toLocaleTimeString()}] → ${id}`, body);
      try {
        const out = await handler(body);
        const state = await buildState();
        console.log(`[${new Date().toLocaleTimeString()}] ✓ ${id}`);
        return sendJson(res, 200, { state, log: out.log });
      } catch (e: any) {
        const msg = extractRevert(e) || e?.message || String(e);
        console.error(`[${new Date().toLocaleTimeString()}] ✗ ${id}: ${msg}`);
        return sendJson(res, 200, { error: msg });
      }
    }

    if (method === 'GET') {
      return serveStatic(req, res);
    }
    res.writeHead(404); res.end('not found');
  } catch (e: any) {
    sendJson(res, 500, { error: e?.message || String(e) });
  }
});

/** Pull a clean revert reason out of ethers' verbose CALL_EXCEPTION dumps. */
function extractRevert(e: any): string | null {
  if (!e) return null;
  if (e.reason) return String(e.reason);
  if (e.shortMessage) return String(e.shortMessage);
  if (e.revert && e.revert.args && e.revert.args.length) return String(e.revert.args[0]);
  return null;
}

const PORT = Number(process.env.GUI_PORT) || 3001;
server.listen(PORT, () => {
  console.log(`Credential Console bridge listening at http://localhost:${PORT}`);
  console.log(`  · issuer wallet:   ${ACTOR_ADDR.issuer || '(no PRIVATE_KEY_ISSUER in .env)'}`);
  console.log(`  · holder wallet:   ${ACTOR_ADDR.holder || '(no PRIVATE_KEY_HOLDER in .env)'}`);
  console.log(`  · verifier wallet: ${ACTOR_ADDR.verifier || '(no PRIVATE_KEY_VERIFIER in .env)'}`);
});
