// Running against a public chain: a provider that survives a slow resolver, and a wallet that records
// every transaction it sends so the real cost (L2 execution + L1 data fee) can be read back afterwards.
import https from 'node:https';
import dns from 'node:dns/promises';
import { readFileSync } from 'node:fs';
import { ethers } from 'ethers';
import { attach, type ContractName, type Deployment } from './client.ts';

const ROOT = new URL('../../../', import.meta.url);

async function resolveOnce(host: string, tries = 5): Promise<string> {
  for (let i = 0; ; i++) {
    try {
      const [ip] = await dns.resolve4(host);
      if (ip) return ip;
    } catch (e) {
      if (i + 1 >= tries) throw e;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

/** JSON-RPC error a public OP Stack endpoint answers with when a client sends too many requests */
const RATE_LIMITED = -32016;

/** retries a request the endpoint refused for rate, with back-off; a refused request was not executed */
class RetryingProvider extends ethers.JsonRpcProvider {
  override async _send(payload: ethers.JsonRpcPayload | ethers.JsonRpcPayload[]): Promise<ethers.JsonRpcResult[]> {
    for (let i = 0; ; i++) {
      const res = await super._send(payload);
      // error responses travel in the same array as results
      const limited = res.some((r) => (r as unknown as { error?: { code?: number } }).error?.code === RATE_LIMITED);
      if (i >= 8 || !limited) return res;
      await new Promise((r) => setTimeout(r, 500 * 2 ** i));
    }
  }
}

/** the host is resolved once and the TLS connection kept alive, so no request pays for a lookup */
export async function liveProvider(url: string, chainId: number): Promise<ethers.JsonRpcProvider> {
  const ip = await resolveOnce(new URL(url).hostname);
  const agent = new https.Agent({
    keepAlive: true,
    maxSockets: 4,
    lookup: (_host, opts, cb) => ((opts as { all?: boolean }).all
      ? (cb as (e: null, a: { address: string; family: number }[]) => void)(null, [{ address: ip, family: 4 }])
      : cb(null, ip, 4)),
  });
  const req = new ethers.FetchRequest(url);
  req.getUrlFunc = ethers.FetchRequest.createGetUrlFunc({ agent });
  req.timeout = 120_000;
  return new RetryingProvider(req, chainId, { staticNetwork: true, pollingInterval: 1000 });
}

export interface SentTx { hash: string; to: string | null; data: string }

export class RecordingWallet extends ethers.Wallet {
  readonly sent: SentTx[] = [];

  override async sendTransaction(tx: ethers.TransactionRequest): Promise<ethers.TransactionResponse> {
    // the node estimates against the latest block; a storage slot the previous block wrote can cost more one
    // block later (e.g. the DID registry's `changed` slot), so leave headroom. A revert still throws here.
    if (tx.gasLimit == null) tx = { ...tx, gasLimit: (await this.estimateGas(tx)) * 6n / 5n };
    const r = await super.sendTransaction(tx);
    this.sent.push({ hash: r.hash, to: r.to, data: r.data });
    return r;
  }
}

export interface TxCost { hash: string; block: number; status: boolean; gasUsed: bigint; l2Fee: bigint; l1Fee: bigint }

/** OP Stack receipts carry the L1 data fee next to the L2 execution fee */
export async function txCost(provider: ethers.JsonRpcProvider, hash: string): Promise<TxCost> {
  const r = await provider.send('eth_getTransactionReceipt', [hash]);
  const gasUsed = BigInt(r.gasUsed);
  return {
    hash,
    block: Number(r.blockNumber),
    status: r.status === '0x1',
    gasUsed,
    l2Fee: gasUsed * BigInt(r.effectiveGasPrice),
    l1Fee: r.l1Fee ? BigInt(r.l1Fee) : 0n,
  };
}

export interface DeploymentFile {
  chain: string; chainId: number; rpc: string; explorer: string; fromBlock: number;
  contracts: Record<ContractName, string>;
}

export interface LiveTarget { dep: DeploymentFile; provider: ethers.JsonRpcProvider; wallet: RecordingWallet; d: Deployment }

/** the contracts in deployments/<chainId>.json, driven by the funded key PRIVATE_KEY from the repository's .env */
export async function connectLive(chainId = 11155420): Promise<LiveTarget> {
  process.loadEnvFile(new URL('.env', ROOT));
  const raw = process.env.PRIVATE_KEY;
  if (!raw) throw new Error('PRIVATE_KEY missing from .env');
  const dep = JSON.parse(readFileSync(new URL(`deployments/${chainId}.json`, ROOT), 'utf8')) as DeploymentFile;
  const provider = await liveProvider(dep.rpc, dep.chainId);
  const wallet = new RecordingWallet(raw.startsWith('0x') ? raw : `0x${raw}`, provider);
  return { dep, provider, wallet, d: attach(dep.contracts, wallet, dep.fromBlock) };
}
