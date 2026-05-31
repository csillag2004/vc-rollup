/* global React */
const { useState, useMemo, useRef, useEffect } = React;

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────
const truncMid = (s, head = 6, tail = 4) => {
  if (!s) return '—';
  if (s.length <= head + tail + 2) return s;
  return s.slice(0, head) + '…' + s.slice(-tail);
};

// ────────────────────────────────────────────────────────────────────
// Input controls
// ────────────────────────────────────────────────────────────────────
function Field({ field, value, onChange }) {
  if (field.kind === 'text') {
    return (
      <div className={`cf-field ${field.width || ''}`}>
        <label>{field.label}</label>
        <input
          type="text"
          value={value || ''}
          placeholder={field.placeholder || ''}
          onChange={(e) => onChange(field.key, e.target.value)}
        />
      </div>
    );
  }
  if (field.kind === 'textarea') {
    return (
      <div className="cf-field">
        <label>{field.label}</label>
        <textarea
          rows={field.rows || 3}
          value={value || ''}
          placeholder={field.placeholder || ''}
          onChange={(e) => onChange(field.key, e.target.value)}
        />
      </div>
    );
  }
  if (field.kind === 'select') {
    return (
      <div className="cf-field">
        <label>{field.label}</label>
        <select
          value={value || ''}
          onChange={(e) => onChange(field.key, e.target.value)}
        >
          <option value="">— {field.placeholder || 'choose'} —</option>
          {field.options.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </div>
    );
  }
  if (field.kind === 'checkboxes') {
    const arr = value || [];
    return (
      <div className="cf-field">
        <label>{field.label}</label>
        <div className="cf-checks">
          {field.options.map((o) => {
            const on = arr.includes(o.value);
            return (
              <button
                type="button"
                key={o.value}
                className={`cf-check ${on ? 'on' : ''}`}
                onClick={() => {
                  const next = on ? arr.filter((x) => x !== o.value) : [...arr, o.value];
                  onChange(field.key, next);
                }}
              >
                <span className="box">{on ? '✓' : ''}</span>
                <span className="lbl">{o.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    );
  }
  return null;
}

// ────────────────────────────────────────────────────────────────────
// Command row — collapsed shows label + run; expanded shows form
// ────────────────────────────────────────────────────────────────────
function CommandRow({ cmd, state, onRun, expanded, onExpand, isSuggested, runningId }) {
  const [values, setValues] = useState({});
  const [error, setError] = useState(null);
  const setVal = (k, v) => {
    setValues((vs) => ({ ...vs, [k]: v }));
    setError(null);
  };

  const baseFields  = cmd.inputs(state);
  const dynaFields  = cmd.dynamicAttrFields ? cmd.dynamicAttrFields(state, values) : [];
  const fields      = [...baseFields, ...dynaFields];
  const blocked     = cmd.canRun(state);
  const isRunningMe        = runningId === cmd.id;
  const someoneElseRunning = !!runningId && runningId !== cmd.id;

  // Effective value for a field: what the user typed, else its computed
  // default (e.g. the auto-incrementing credId).
  const effVal = (f) => (values[f.key] !== undefined ? values[f.key] : f.default);

  const submit = async () => {
    if (isRunningMe || someoneElseRunning) return;
    // Send defaults for any field the user left untouched, so an
    // auto-populated value (like credId) is submitted as shown.
    const payload = {};
    for (const f of fields) payload[f.key] = effVal(f);
    const r = await onRun(cmd, payload);
    if (r && r.error) {
      setError(r.error);
    } else {
      setError(null);
      // Keep selects sticky (so they don't reset between calls), but clear text fields
      const sticky = {};
      for (const f of baseFields) {
        if (f.kind === 'select') sticky[f.key] = values[f.key];
      }
      setValues(sticky);
    }
  };

  return (
    <div className={`cmd ${expanded ? 'open' : ''} ${blocked ? 'blocked' : ''} ${isSuggested ? 'suggested' : ''} ${isRunningMe ? 'running' : ''}`}>
      <button type="button" className="cmd-head" onClick={() => onExpand()}>
        <span className="caret">{expanded ? '▾' : '▸'}</span>
        <span className="cmd-name-wrap">
          <span className="cmd-name">{cmd.label}</span>
          {blocked && <span className="cmd-block" title={blocked}>{blocked}</span>}
        </span>
        {isSuggested && <span className="cmd-suggest">next</span>}
      </button>

      {expanded && (
        <div className="cmd-body">
          {fields.length === 0 ? (
            <p className="muted serif" style={{fontStyle: 'italic', fontSize: 12, margin: '4px 0 8px'}}>
              No inputs — this function takes none.
            </p>
          ) : (
            <div className="cmd-form">
              {fields.map((f) => (
                <Field key={f.key} field={f} value={effVal(f)} onChange={setVal} />
              ))}
            </div>
          )}
          {error && <div className="cmd-error">! {error}</div>}
          <div className="cmd-actions">
            <button
              type="button"
              className={`btn primary ${blocked || someoneElseRunning ? 'disabled' : ''}`}
              onClick={submit}
              disabled={!!blocked || isRunningMe || someoneElseRunning}
            >
              {isRunningMe ? (<>Running… <span className="cmd-spinner" /></>) : (<>Run {cmd.label}</>)}
            </button>
            {blocked && <span className="muted" style={{fontSize: 11, alignSelf: 'center'}}>{blocked}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Sidebar — persistent world state
// ────────────────────────────────────────────────────────────────────
function Sidebar({ state }) {
  const schemas    = Object.values(state.schemas);
  const credDefs   = Object.values(state.credDefs);
  const registries = Object.values(state.registries);
  const creds      = Object.values(state.credentials);

  return (
    <aside className="sidebar">
      <p className="eyebrow">World State · Scroll Sepolia</p>

      <h3>Accumulator</h3>
      {state.accumulator ? (
        <>
          <div className="sb-kv"><span className="k">value</span><span className="v">{truncMid(state.accumulator.value, 10, 8)}</span></div>
          <div className="sb-kv"><span className="k">epoch</span><span className="v">{state.accumulator.epoch}</span></div>
          <div className="sb-kv"><span className="k">pubkey</span><span className="v">{truncMid(state.accumulator.pubKey, 8, 6)}</span></div>
        </>
      ) : <div className="muted mono empty">not yet initialised</div>}

      <h3>Schemas <span className="ct">{schemas.length}</span></h3>
      {schemas.length === 0 ? <div className="muted mono empty">—</div> : (
        <ul className="sb-list">
          {schemas.map((s) => (
            <li key={s.id}>
              <span className="name">{s.name} <span className="muted mono" style={{fontSize: 10}}>v{s.version}</span></span>
              <span className="meta">{s.attributes.length} attrs</span>
            </li>
          ))}
        </ul>
      )}

      <h3>CredDefs <span className="ct">{credDefs.length}</span></h3>
      {credDefs.length === 0 ? <div className="muted mono empty">—</div> : (
        <ul className="sb-list">
          {credDefs.map((c) => (
            <li key={c.id}>
              <span className="name">{state.schemas[c.schemaId]?.name || '?'}<span className="muted mono" style={{fontSize: 10}}> · {c.tag}</span></span>
              <span className="meta">{truncMid(c.id, 6, 4)}</span>
            </li>
          ))}
        </ul>
      )}

      <h3>Registries <span className="ct">{registries.length}</span></h3>
      {registries.length === 0 ? <div className="muted mono empty">—</div> : (
        <ul className="sb-list">
          {registries.map((r) => (
            <li key={r.id}>
              <span className="name">{state.schemas[r.schemaId]?.name || '?'}</span>
              <span className="meta">{truncMid(r.id, 6, 4)}</span>
            </li>
          ))}
        </ul>
      )}

      <h3>Credentials <span className="ct">{creds.length}</span></h3>
      {creds.length === 0 ? <div className="muted mono empty">none issued</div> : (
        <div>
          {creds.map((c) => (
            <div className="cred-row" key={c.credId}>
              <div className="cred-head">
                <span className="cred-name">{c.name || c.credId}</span>
                <span className={`status ${c.status}`}>{c.status}</span>
              </div>
              <div className="cred-sub">
                <span>y={c.y}</span>
                <span style={{marginLeft: 'auto'}}>
                  {c.signed     ? <span className="chip">σ</span>     : null}
                  {c.witnessed  ? <span className="chip">w</span>     : null}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </aside>
  );
}

// ────────────────────────────────────────────────────────────────────
// Generic panel that renders a list of grouped commands
// ────────────────────────────────────────────────────────────────────
function ActorPanel({ role, no, addr, blurb, commands, state, expanded, setExpanded, onRun, suggestedId, summary, runningId }) {
  // group by `group`
  const groups = useMemo(() => {
    const g = {};
    for (const c of commands) {
      if (!g[c.group]) g[c.group] = [];
      g[c.group].push(c);
    }
    return g;
  }, [commands]);

  return (
    <section className="panel">
      <header className="panel-head">
        <span className="role">The <em>{role}</em></span>
        <span className="role-no">Actor {no}<br/>{addr.slice(0, 10)}…</span>
      </header>
      <div className="panel-body">
        {summary}

        {Object.entries(groups).map(([gname, cmds]) => (
          <div className="func-group" key={gname}>
            <div className="gh"><span>{gname}</span><span className="gh-no">{cmds.length} function{cmds.length !== 1 ? 's' : ''}</span></div>
            {cmds.map((c) => (
              <CommandRow
                key={c.id}
                cmd={c}
                state={state}
                onRun={onRun}
                expanded={expanded === c.id}
                onExpand={() => setExpanded(expanded === c.id ? null : c.id)}
                isSuggested={suggestedId === c.id}
                runningId={runningId}
              />
            ))}
          </div>
        ))}
      </div>
    </section>
  );
}

// ────────────────────────────────────────────────────────────────────
// Issuer summary block (no extra state to show, but a registrar identity)
// ────────────────────────────────────────────────────────────────────
function IssuerSummary({ state }) {
  return null;
}

// ────────────────────────────────────────────────────────────────────
// Holder summary — the wallet
// ────────────────────────────────────────────────────────────────────
function HolderWallet({ state }) {
  const items = Object.values(state.holderInbox);
  return (
    <div className="func-group">
      <div className="gh"><span>Wallet</span><span className="gh-no">{items.length || 'empty'}</span></div>
      {items.length === 0 ? (
        <div className="muted serif" style={{fontStyle: 'italic', fontSize: 12, padding: '6px 4px'}}>
          Awaiting credentials from the issuer.
        </div>
      ) : (
        <div style={{display: 'grid', gap: 6}}>
          {items.map((c) => {
            const cred = state.credentials[c.credId];
            const revoked = cred && cred.status === 'revoked';
            return (
              <div className="result-block incoming" key={c.credId} style={{margin: 0}}>
                <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'baseline'}}>
                  <span><span className="kk">{c.name || c.credId}</span></span>
                  {revoked && <span className="status revoked">revoked</span>}
                </div>
                <div><span className="kk">schema</span>{state.schemas[c.schemaId]?.name || '?'}</div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Verifier summary — inbox + last verification
// ────────────────────────────────────────────────────────────────────
function VerifierInbox({ state }) {
  const proofs = state.verifierInbox.proofs;
  const last   = state.verifierInbox.lastVerified;
  return (
    <>
      <div className="func-group">
        <div className="gh"><span>Inbox</span><span className="gh-no">{proofs.length || 'empty'} pending</span></div>
        {proofs.length === 0 ? (
          <div className="muted serif" style={{fontStyle: 'italic', fontSize: 12, padding: '6px 4px'}}>
            Awaiting composite proof from the holder.
          </div>
        ) : (
          <div style={{display: 'grid', gap: 6}}>
            {proofs.map((p, i) => {
              const sch = state.schemas[p.schemaId];
              return (
                <div className="result-block incoming" key={i} style={{margin: 0}}>
                  <div><span className="kk">{p.name || p.credId}</span></div>
                  <div><span className="kk">reveals</span>
                    {p.revealed.length === 0
                      ? <span className="muted">none</span>
                      : p.revealed.map((idx) => sch?.attributes[idx]).filter(Boolean).join(', ')
                    }
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {last && (
        <div className={`result-block ${last.isValid ? 'success' : 'revoke'}`}>
          <div style={{fontFamily: 'var(--f-serif)', fontSize: 14, fontStyle: 'italic', marginBottom: 4}}>
            {last.isValid ? '✓ Verification successful' : '✗ Verification failed'}
          </div>
          <div><span className="kk">credential</span>{last.name || last.credId}</div>
          {state.schemas[last.schemaId]?.attributes.map((a, i) => {
            const isRevealed = last.revealed.includes(i);
            const v = isRevealed ? last.revealedMap[a] : null;
            return (
              <div key={a}>
                <span className="kk">{a}</span>
                {isRevealed
                  ? <span style={{color: 'var(--accent)', fontWeight: 600}}>{v}</span>
                  : <span style={{color: 'var(--ink-faint)'}}>(zero-knowledge — not disclosed)</span>}
              </div>
            );
          })}
          <div><span className="kk">accumulator</span>{last.isValid ? `membership holds at epoch ${state.accumulator?.epoch}` : 'membership FAILED'}</div>
        </div>
      )}
    </>
  );
}

// ────────────────────────────────────────────────────────────────────
// Connector arrow between panels
// ────────────────────────────────────────────────────────────────────
function Connector({ active, label }) {
  return (
    <div className="connector">
      <div className={`line ${active ? 'active' : ''}`} />
      {label && <div className="arrow-label">{label}</div>}
      <div className={`arrow ${active ? 'active' : ''}`}>→</div>
    </div>
  );
}

Object.assign(window, {
  Sidebar, ActorPanel, HolderWallet, VerifierInbox, Connector, truncMid,
});
