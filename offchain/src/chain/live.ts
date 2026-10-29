// Running against a public chain: a provider that survives a slow resolver, and a wallet that records
// every transaction it sends so the real cost (L2 execution + L1 data fee) can be read back afterwards.
import https from 'node:https';
import dns from 'node:dns/promises';
import { ethers } from 'ethers';

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
  return new ethers.JsonRpcProvider(req, chainId, { staticNetwork: true, pollingInterval: 1000 });
}

export interface SentTx { hash: string; to: string | null; data: string }

export class RecordingWallet extends ethers.Wallet {
  readonly sent: SentTx[] = [];

  override async sendTransaction(tx: ethers.TransactionRequest): Promise<ethers.TransactionResponse> {
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
