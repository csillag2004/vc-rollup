// Commands — same structure as the design, but every run() POSTs to the
// local bridge in gui/server.ts, which calls the real Issuer/Holder/Verifier.

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────
const parseAttributes = (raw) =>
  String(raw || '')
    .split(/[,\n]/g)
    .map((s) => s.trim())
    .filter(Boolean);

const newCredId = (state) => {
  let i = 1;
  while (
    (state.credentials && state.credentials[`cred${i}`]) ||
    (state.holderInbox && state.holderInbox[`cred${i}`])
  ) {
    i++;
  }
  return `cred${i}`;
};

const optionsFromMap = (m, labelKey) =>
  Object.values(m || {}).map((v) => ({
    value: v.id || v.credId,
    label: labelKey ? v[labelKey] : (v.id || v.credId),
  }));

const SCROLL_BLOCK_BASE = 0; // unused — server snapshot provides real block info

const INITIAL_STATE = {
  accumulator: null,
  schemas: {}, credDefs: {}, registries: {}, credentials: {},
  witnesses: {}, holderInbox: {},
  verifierInbox: { proofs: [], lastVerified: null },
  txCount: 0,
  events: 0,
  actors: { issuer: '', holder: '', verifier: '' },
  block: null,
};

// Default placeholders shown in the masthead before /api/state arrives
const ACTOR_ADDR = { issuer: '', holder: '', verifier: '' };

// ────────────────────────────────────────────────────────────────────
// Backend bridge
// ────────────────────────────────────────────────────────────────────
async function fetchState() {
  const resp = await fetch('/api/state');
  if (!resp.ok) throw new Error('state fetch failed');
  return await resp.json();
}

async function runOnServer(commandId, values) {
  let resp;
  try {
    resp = await fetch('/api/run/' + commandId, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(values || {}),
    });
  } catch (e) {
    return { error: 'cannot reach gui/server.ts — is it running?' };
  }
  let json = {};
  try { json = await resp.json(); } catch (_) {}
  if (!resp.ok) {
    return { error: json.error || `HTTP ${resp.status}` };
  }
  return json; // { state, log, message? }
}

// ────────────────────────────────────────────────────────────────────
// COMMAND SPECS
// Each: { id, actor, group, label, blurb,
//         inputs(state) → [field defs],
//         dynamicAttrFields(state, values) → [field defs] (optional),
//         canRun(state) → null|reason,
//         run(state, values) → Promise<{ state?, log?, message?, error? }> }
// ────────────────────────────────────────────────────────────────────
const COMMANDS = [
  // ============ ISSUER · SETUP ============
  {
    id: 'initAccumulator',
    actor: 'issuer', group: 'Setup',
    label: 'Initialise Accumulator',
    blurb: 'Generates VB-accumulator params + keypair and publishes them on Scroll Sepolia. Running this again overwrites the on-chain accumulator with fresh values — any previously issued credentials become unverifiable.',
    inputs: () => [],
    canRun: () => null,
    run: (s, v) => runOnServer('initAccumulator', v),
  },

  {
    id: 'registerSchema',
    actor: 'issuer', group: 'Setup',
    label: 'Register Schema',
    blurb: 'Publishes a credential schema on SchemaRegistry.',
    inputs: () => [
      { key: 'name',       label: 'Schema name',  kind: 'text',     placeholder: 'e.g. UniversityDegree' },
      { key: 'version',    label: 'Version',      kind: 'text',     placeholder: 'e.g. 1.0', width: 'sm' },
      { key: 'attributes', label: 'Attributes',   kind: 'textarea', placeholder: 'one per line — e.g.\nstudentName\nuniversity\ndegree\ngraduationYear', rows: 4 },
    ],
    canRun: (s) => s.accumulator ? null : 'accumulator not yet initialised',
    run: (s, v) => runOnServer('registerSchema', v),
  },

  {
    id: 'registerCredDef',
    actor: 'issuer', group: 'Setup',
    label: 'Register CredDef',
    blurb: 'Binds BBS+ signing keys to a schema.',
    inputs: (s) => [
      { key: 'schemaId', label: 'Schema',  kind: 'select', options: optionsFromMap(s.schemas, 'name'), placeholder: 'pick a schema' },
      { key: 'tag',      label: 'Tag',     kind: 'text',   placeholder: 'e.g. default', width: 'sm' },
    ],
    canRun: (s) => Object.keys(s.schemas).length ? null : 'register a schema first',
    run: (s, v) => runOnServer('registerCredDef', v),
  },

  {
    id: 'createRegistry',
    actor: 'issuer', group: 'Setup',
    label: 'Create Revocation Registry',
    blurb: 'Wires a registry to the on-chain accumulator.',
    inputs: (s) => [
      { key: 'credDefId', label: 'Credential definition', kind: 'select',
        options: Object.values(s.credDefs).map((c) => ({
          value: c.id,
          label: `${(s.schemas[c.schemaId] && s.schemas[c.schemaId].name) || c.schemaId.slice(0,10)} · ${c.tag}`,
        })),
        placeholder: 'pick a credDef' },
    ],
    canRun: (s) => Object.keys(s.credDefs).length ? null : 'register a credDef first',
    run: (s, v) => runOnServer('createRegistry', v),
  },

  // ============ ISSUER · ISSUANCE ============
  {
    id: 'issueCredential',
    actor: 'issuer', group: 'Issuance',
    label: 'Issue Credential',
    blurb: 'Adds a new member y to the accumulator and records the holder.',
    inputs: (s) => [
      { key: 'registryId', label: 'Registry', kind: 'select',
        options: Object.values(s.registries).map((r) => ({
          value: r.id,
          label: `${(s.schemas[r.schemaId] && s.schemas[r.schemaId].name) || ''} · ${r.id.slice(0,10)}…`,
        })),
        placeholder: 'pick a registry' },
      { key: 'credId',     label: 'Credential ID', kind: 'text', placeholder: `e.g. ${newCredId(s)}`, width: 'sm' },
      { key: 'holderName', label: 'Holder name',   kind: 'text', placeholder: 'e.g. Alice Tarr' },
    ],
    dynamicAttrFields: (s, values) => {
      const reg = s.registries[values.registryId];
      if (!reg) return [];
      const sch = s.schemas[reg.schemaId];
      if (!sch) return [];
      return sch.attributes.map((a, i) => ({
        key: `attr:${i}`,
        label: a,
        kind: 'text',
        placeholder: `value for ${a}`,
      }));
    },
    canRun: (s) => Object.keys(s.registries).length ? null : 'create a registry first',
    run: (s, v) => runOnServer('issueCredential', v),
  },

  // ============ ISSUER · REVOCATION ============
  {
    id: 'revokeCredential',
    actor: 'issuer', group: 'Revocation',
    label: 'Revoke Credential',
    blurb: 'Removes y from the accumulator; the credential is no longer a member.',
    inputs: (s) => [
      { key: 'credId', label: 'Credential', kind: 'select',
        options: Object.values(s.credentials).filter((c) => c.status === 'active').map((c) => ({
          value: c.credId,
          label: `${c.credId} · ${c.holderName || ''}`,
        })),
        placeholder: 'pick a credential' },
    ],
    canRun: (s) => Object.values(s.credentials).some((c) => c.status === 'active') ? null : 'no active credentials',
    run: (s, v) => runOnServer('revokeCredential', v),
  },

  // ============ ISSUER · PRESENTATION SUPPORT ============
  {
    id: 'createWitness',
    actor: 'issuer', group: 'Presentation Support',
    label: 'Create Witness',
    blurb: 'Computes the holder’s VB-membership witness against the current accumulator.',
    inputs: (s) => [
      { key: 'credId', label: 'Credential', kind: 'select',
        options: Object.values(s.credentials).filter((c) => c.status === 'active').map((c) => ({
          value: c.credId,
          label: `${c.credId} · ${c.holderName || ''}`,
        })),
        placeholder: 'pick a credential' },
    ],
    canRun: (s) => Object.values(s.credentials).some((c) => c.status === 'active') ? null : 'no active credentials',
    run: (s, v) => runOnServer('createWitness', v),
  },

  {
    id: 'signCredential',
    actor: 'issuer', group: 'Presentation Support',
    label: 'Sign Credential',
    blurb: 'BBS+ signs the attribute vector and delivers (σ + witness) to the holder.',
    inputs: (s) => [
      { key: 'credId', label: 'Credential', kind: 'select',
        options: Object.values(s.credentials).filter((c) => c.witnessed).map((c) => ({
          value: c.credId,
          label: `${c.credId} · ${c.holderName || ''}`,
        })),
        placeholder: 'pick a credential' },
    ],
    canRun: (s) => Object.values(s.credentials).some((c) => c.witnessed) ? null : 'create a witness first',
    run: (s, v) => runOnServer('signCredential', v),
  },

  // ============ HOLDER ============
  {
    id: 'updateWitness',
    actor: 'holder', group: 'Witness Synchronisation',
    label: 'Update Witness',
    blurb: 'Replays AccumulatorUpdated events to bring the witness to the current epoch.',
    inputs: (s) => [
      { key: 'credId', label: 'Credential', kind: 'select',
        options: Object.values(s.holderInbox).map((c) => ({
          value: c.credId,
          label: `${c.credId} · ${c.holderName || ''} (${c.witnessSynced ? 'synced' : 'stale'})`,
        })),
        placeholder: 'pick a credential' },
    ],
    canRun: (s) => Object.keys(s.holderInbox).length ? null : 'wallet is empty',
    run: (s, v) => runOnServer('updateWitness', v),
  },

  {
    id: 'generateProof',
    actor: 'holder', group: 'Selective Disclosure',
    label: 'Generate Composite Proof',
    blurb: 'BBS+ proof of knowledge + accumulator-membership ZKP, with chosen attributes revealed.',
    inputs: (s) => [
      { key: 'credId', label: 'Credential', kind: 'select',
        options: Object.values(s.holderInbox).map((c) => ({
          value: c.credId,
          label: `${c.credId} · ${c.holderName || ''}`,
        })),
        placeholder: 'pick a credential' },
    ],
    dynamicAttrFields: (s, values) => {
      const h = s.holderInbox[values.credId];
      if (!h) return [];
      const sch = s.schemas[h.schemaId];
      if (!sch) return [];
      return [{
        key: 'reveal',
        label: 'Reveal which attributes?',
        kind: 'checkboxes',
        options: sch.attributes.map((a, i) => ({ value: String(i), label: a })),
      }];
    },
    canRun: (s) => Object.keys(s.holderInbox).length ? null : 'wallet is empty',
    run: (s, v) => runOnServer('generateProof', v),
  },

  // ============ VERIFIER ============
  {
    id: 'verifyProof',
    actor: 'verifier', group: 'Verification',
    label: 'Verify Composite Proof',
    blurb: 'Rebuilds the verifier spec from on-chain registries; checks the proof against the live accumulator.',
    inputs: (s) => [
      { key: 'credId', label: 'Pending proof', kind: 'select',
        options: s.verifierInbox.proofs.map((p) => ({
          value: p.credId,
          label: `${p.credId} · ${p.holderName || ''}`,
        })),
        placeholder: 'pick a proof' },
    ],
    canRun: (s) => s.verifierInbox.proofs.length ? null : 'inbox is empty',
    run: (s, v) => runOnServer('verifyProof', v),
  },
];

window.DEMO = {
  COMMANDS,
  INITIAL_STATE,
  ACTOR_ADDR,
  SCROLL_BLOCK_BASE,
  parseAttributes,
  newCredId,
  fetchState,
};
