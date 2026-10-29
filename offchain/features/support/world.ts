// Shared state of one scenario. The contracts are deployed once per run; every scenario gets its own
// funded landlord account, so its schema, CredDef and policy bindings never collide with another's.
import { setWorldConstructor, setDefaultTimeout, BeforeAll, Before, World, type IWorldOptions } from '@cucumber/cucumber';
import { ethers } from 'ethers';
import { deployAll, revertName, type Deployment } from '../../src/chain/client.ts';
import { Issuer, Holder, Verifier, type PolicyRef } from '../../src/actors/actors.ts';
import type { Analysis, Binding, Presentation } from '../../src/ql/compile.ts';

const RPC = process.env.RPC ?? 'http://127.0.0.1:8545';
// anvil's first default account (a public test key): deploys the contracts and nothing else
const DEPLOYER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

setDefaultTimeout(180_000);

let provider: ethers.JsonRpcProvider;
let deployment: Deployment;

BeforeAll(async function () {
  provider = new ethers.JsonRpcProvider(RPC, undefined, { pollingInterval: 50, cacheTimeout: -1 });
  try {
    await provider.getBlockNumber();
  } catch {
    throw new Error(`no chain at ${RPC}: start one with  anvil --hardfork prague`);
  }
  deployment = await deployAll(new ethers.Wallet(DEPLOYER_KEY, provider));
});

export interface Outcome { what: string; ok: boolean; error?: string }
export interface Proof { who: string; query: string; bindings: [string, Binding][]; p: Presentation }

export class ReservationWorld extends World {
  d!: Deployment;
  landlord!: Issuer;
  verifier!: Verifier;
  readonly schemas = new Map<string, string>();
  registryId = '';
  readonly holders = new Map<string, Holder>();
  readonly groups = new Map<string, Binding>();
  policy?: PolicyRef;
  readonly guards = new Map<string, Presentation>();
  readonly outcomes: Outcome[] = [];
  lastProof?: Proof;
  lastVerify?: Awaited<ReturnType<Verifier['verify']>>;
  analysis?: Analysis;
  label = '';

  constructor(options: IWorldOptions) { super(options); }

  /** run a write and record whether the chain accepted it, with the contract's error name if not */
  async attempt(what: string, fn: () => Promise<unknown>): Promise<Outcome> {
    let o: Outcome;
    try {
      await fn();
      o = { what, ok: true };
    } catch (e) {
      o = { what, ok: false, error: revertName(this.d, e) };
    }
    this.outcomes.push(o);
    return o;
  }

  last(): Outcome {
    const o = this.outcomes[this.outcomes.length - 1];
    if (!o) throw new Error('no write attempted yet');
    return o;
  }

  holder(name: string): Holder {
    const h = this.holders.get(name);
    if (!h) throw new Error(`no holder ${name}`);
    return h;
  }

  /** the revocation ID of the holder's (first) credential */
  y(name: string): bigint { return this.holder(name).wallet[0]!.scalars[0]!; }

  group(name: string): Binding & { kind: 'group' } {
    const g = this.groups.get(name);
    if (!g || g.kind !== 'group') throw new Error(`no group ${name}`);
    return g;
  }

  /** bindings every query of the flat reservation may use */
  bindings(): [string, Binding][] {
    return [['S', this.group('S')], ['Landlord', { kind: 'creddef', credDefId: this.landlord.credDefId }]];
  }
}

setWorldConstructor(ReservationWorld);

Before(async function (this: ReservationWorld, { pickle }) {
  this.d = deployment;
  this.verifier = new Verifier(deployment);
  this.label = `${pickle.name}-${pickle.id}`;
  const w = ethers.Wallet.createRandom().connect(provider);
  await provider.send('anvil_setBalance', [w.address, ethers.toQuantity(ethers.parseEther('100'))]);
  // every transaction is awaited, so the provider's nonce is always current
  this.landlord = new Issuer(w, deployment);
});
