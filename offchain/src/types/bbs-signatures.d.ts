// Minimal typing of the parts of @digitalbazaar/bbs-signatures we use.
declare module '@digitalbazaar/bbs-signatures' {
  export const CIPHERSUITES: { BLS12381_SHA256: string; BLS12381_SHAKE256: string };
  export function generateKeyPair(o: { ciphersuite: string; seed?: Uint8Array }): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }>;
  export function sign(o: { secretKey: Uint8Array; publicKey: Uint8Array; header: Uint8Array; messages: Uint8Array[]; ciphersuite: string }): Promise<Uint8Array>;
  export function verifySignature(o: { publicKey: Uint8Array; signature: Uint8Array; header: Uint8Array; messages: Uint8Array[]; ciphersuite: string }): Promise<boolean>;
}
