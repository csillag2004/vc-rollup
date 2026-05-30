/* global React, ReactDOM */
/* global Sidebar, ActorPanel, HolderWallet, VerifierInbox */
/* global TweaksPanel, useTweaks, TweakSection, TweakToggle, TweakRadio, TweakButton */
const { useState, useEffect, useRef, useMemo, useCallback } = React;

// ────────────────────────────────────────────────────────────────────
// Activity log
// ────────────────────────────────────────────────────────────────────
const TAG_LABEL = { tx: 'TX', ok: 'OK', warn: 'WARN', info: 'INFO', err: 'ERR' };
const tagFor = (k) => TAG_LABEL[k] || '·';

function ActivityLog({ lines, verbosity, blockInfo }) {
  const stream = useRef(null);
  useEffect(() => {
    if (stream.current) stream.current.scrollTop = stream.current.scrollHeight;
  }, [lines.length]);

  return (
    <section className="log">
      <div className="log-head">
        <div>
          <div className="title">Activity Log</div>
          <div className="meta" style={{marginTop: 4}}>Scroll Sepolia · live tail</div>
        </div>
        <div>
          <div className="meta">{lines.length} entries</div>
        </div>
      </div>
      <div className="log-stream" ref={stream}>
        {lines.length === 0 ? (
          <div className="log-line intro">
            <span /><span /><span />
            <span className="msg">Initialise the accumulator on the issuer panel to begin.</span>
            <span />
          </div>
        ) : lines.map((ln, i) => (
          <div key={i} className={`log-line kind-${ln.kind}`}>
            <span className="t">{ln.t}</span>
            <span className="tag">{tagFor(ln.kind)}</span>
            <span className="actor">{ln.actor || '·'}</span>
            <span className="msg">
              {ln.msg}
              {verbosity === 'raw' && ln.hash && <span style={{color: 'var(--ink-ghost)'}}> ({ln.hash})</span>}
            </span>
            <span>
              {ln.hash && verbosity !== 'raw' && (
                <a className="hash" href={`https://sepolia.scrollscan.com/tx/${ln.hash}`} target="_blank" rel="noreferrer">
                  {ln.hash.slice(0, 10)}…{ln.hash.slice(-6)}
                </a>
              )}
            </span>
          </div>
        ))}
      </div>
      <div className="log-side">
        <div className="meta" style={{marginBottom: 4}}>Chain</div>
        <div style={{fontFamily: 'var(--f-mono)', fontSize: 11, color: 'var(--ink)'}}>Scroll Sepolia</div>
        <div style={{fontFamily: 'var(--f-mono)', fontSize: 10, color: 'var(--ink-faint)'}}>chainId 534351</div>
        <div className="meta" style={{marginTop: 8, marginBottom: 4}}>Block</div>
        <div style={{fontFamily: 'var(--f-mono)', fontSize: 11, color: 'var(--ink)'}}>
          {blockInfo != null ? Number(blockInfo).toLocaleString() : '—'}
        </div>
      </div>
    </section>
  );
}

// ────────────────────────────────────────────────────────────────────
// Suggestion engine — same heuristic as the design
// ────────────────────────────────────────────────────────────────────
function suggestNext(state) {
  if (!state.accumulator)                          return 'initAccumulator';
  if (Object.keys(state.schemas).length === 0)     return 'registerSchema';
  if (Object.keys(state.credDefs).length === 0)    return 'registerCredDef';
  if (Object.keys(state.registries).length === 0)  return 'createRegistry';
  if (Object.keys(state.credentials).length === 0) return 'issueCredential';

  if (state.verifierInbox.proofs.length > 0
      && (!state.verifierInbox.lastVerified
          || state.verifierInbox.lastVerified.credId !== state.verifierInbox.proofs[state.verifierInbox.proofs.length - 1].credId)) {
    return 'verifyProof';
  }
  const holderItems = Object.values(state.holderInbox);
  if (holderItems.some((h) => h.witnessSynced) && state.verifierInbox.proofs.length === 0) {
    return 'generateProof';
  }
  if (holderItems.some((h) => !h.witnessSynced)) return 'updateWitness';
  const creds = Object.values(state.credentials);
  if (creds.some((c) => c.status === 'active' && !c.witnessed)) return 'createWitness';
  if (creds.some((c) => c.witnessed && !c.signed))              return 'signCredential';
  return null;
}

// ────────────────────────────────────────────────────────────────────
// Main App
// ────────────────────────────────────────────────────────────────────
function App() {
  const { COMMANDS, INITIAL_STATE, fetchState } = window.DEMO;

  const [t, setTweak] = useTweaks(/*EDITMODE-BEGIN*/{
    "density": "roomy",
    "verbosity": "normal",
    "showSuggestions": true
  }/*EDITMODE-END*/);

  const [state, setState] = useState(INITIAL_STATE);
  const [lines, setLines] = useState([]);
  const [expanded, setExpanded] = useState({ issuer: null, holder: null, verifier: null });
  const [runningId, setRunningId] = useState(null);
  const [conn, setConn] = useState({ status: 'connecting', err: null });

  // Initial state fetch
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const s = await fetchState();
        if (!cancelled) {
          setState(s);
          setConn({ status: 'ok', err: null });
        }
      } catch (e) {
        if (!cancelled) setConn({ status: 'err', err: 'cannot reach gui/server.ts on this port' });
      }
    })();
    return () => { cancelled = true; };
  }, [fetchState]);

  const issuerCmds   = useMemo(() => COMMANDS.filter((c) => c.actor === 'issuer'),   []);
  const holderCmds   = useMemo(() => COMMANDS.filter((c) => c.actor === 'holder'),   []);
  const verifierCmds = useMemo(() => COMMANDS.filter((c) => c.actor === 'verifier'), []);

  const setExpanded_ = (actor) => (id) => setExpanded((e) => ({ ...e, [actor]: id }));

  const suggestedId = useMemo(() => suggestNext(state), [state]);

  const stamp = () => new Date().toLocaleTimeString('en-GB', { hour12: false });

  const runCommand = useCallback(async (cmd, values) => {
    const blocked = cmd.canRun(state);
    if (blocked) return { error: blocked };

    setRunningId(cmd.id);
    setLines((ls) => [...ls, { t: stamp(), kind: 'info', actor: cmd.actor, msg: `${cmd.label} — sending transaction…` }]);

    let r;
    try {
      r = await cmd.run(state, values);
    } catch (e) {
      r = { error: (e && e.message) || String(e) };
    }
    setRunningId(null);

    if (r && r.error) {
      setLines((ls) => [...ls, { t: stamp(), kind: 'err', actor: cmd.actor, msg: r.error }]);
      setConn((c) => c.status === 'err' ? c : { status: 'ok', err: null });
      return { error: r.error };
    }

    setConn({ status: 'ok', err: null });
    const newLines = (r.log || []).map((l) => ({ t: stamp(), ...l }));
    if (newLines.length) setLines((ls) => [...ls, ...newLines]);
    if (r.state) setState(r.state);
    return { ok: true };
  }, [state]);

  const reset = useCallback(async () => {
    setRunningId('reset');
    try {
      const resp = await fetch('/api/reset', { method: 'POST' });
      const json = await resp.json();
      setState(json.state || INITIAL_STATE);
      setLines([]);
      setExpanded({ issuer: null, holder: null, verifier: null });
    } catch (e) {
      // ignore; world stays as-is
    }
    setRunningId(null);
  }, []);

  const appClass = [
    'app',
    t.density === 'compact' ? 'compact' : '',
    t.showSuggestions ? '' : 'no-suggestions',
  ].filter(Boolean).join(' ');

  const actorAddr = state.actors || { issuer: '', holder: '', verifier: '' };

  return (
    <div className={appClass}>
      <header className="masthead">
        <div className="title">Credential <em>Console</em></div>
        <div className={`conn-pill ${conn.status}`}>
          {conn.status === 'ok' ? 'online' : conn.status === 'connecting' ? 'connecting' : 'offline'}
        </div>
      </header>

      {conn.status === 'err' && (
        <div className="offline-banner">! {conn.err} — start the bridge with: <span style={{fontFamily: 'var(--f-mono)'}}>npx ts-node gui/server.ts</span></div>
      )}

      <div className="body">
        <Sidebar state={state} />
        <div className="stage">
          <ActorPanel
            role="Issuer"  no="01" addr={actorAddr.issuer || '0x…'}
            blurb="The registrar. Owns the BBS+ signing keys, controls the on-chain accumulator, and decides who is listed or removed."
            commands={issuerCmds} state={state}
            expanded={expanded.issuer} setExpanded={setExpanded_('issuer')}
            onRun={runCommand} runningId={runningId}
            suggestedId={t.showSuggestions ? suggestedId : null}
          />
          <ActorPanel
            role="Holder"  no="02" addr={actorAddr.holder || '0x…'}
            blurb="The graduate. Holds the BBS+ signature and a fresh membership witness. Decides what to disclose."
            commands={holderCmds} state={state}
            expanded={expanded.holder} setExpanded={setExpanded_('holder')}
            onRun={runCommand} runningId={runningId}
            suggestedId={t.showSuggestions ? suggestedId : null}
            summary={<HolderWallet state={state} />}
          />
          <ActorPanel
            role="Verifier" no="03" addr={actorAddr.verifier || '0x…'}
            blurb="A prospective employer. Trusts no one off-chain — reconstructs the proof spec from on-chain registries and checks it."
            commands={verifierCmds} state={state}
            expanded={expanded.verifier} setExpanded={setExpanded_('verifier')}
            onRun={runCommand} runningId={runningId}
            suggestedId={t.showSuggestions ? suggestedId : null}
            summary={<VerifierInbox state={state} />}
          />
        </div>
      </div>

      <ActivityLog lines={lines} verbosity={t.verbosity} blockInfo={state.block} />

      <div className="floating-controls">
        <button className="btn ghost" onClick={reset} disabled={runningId === 'reset'}>
          {runningId === 'reset' ? 'Resetting…' : 'Reset world'}
        </button>
      </div>

      <TweaksPanel title="Tweaks">
        <TweakSection label="Layout">
          <TweakRadio label="Density" value={t.density}
                      options={[{value:'roomy', label:'Roomy'},{value:'compact', label:'Compact'}]}
                      onChange={(v) => setTweak('density', v)} />
          <TweakToggle label="Highlight ‘next’ suggestion" value={t.showSuggestions}
                       onChange={(v) => setTweak('showSuggestions', v)} />
        </TweakSection>
        <TweakSection label="Activity Log">
          <TweakRadio label="Verbosity" value={t.verbosity}
                      options={[{value:'normal', label:'Normal'},{value:'raw', label:'Raw hex'}]}
                      onChange={(v) => setTweak('verbosity', v)} />
        </TweakSection>
        <TweakSection label="World">
          <TweakButton label="Reset GUI mirror (clear log only)"
                       onClick={() => { setLines([]); }} />
        </TweakSection>
      </TweaksPanel>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
