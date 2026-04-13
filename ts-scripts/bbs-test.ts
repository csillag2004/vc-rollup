import { //könyvtárak importálása
  generateBls12381G2KeyPair, //kulcsgenerálás
  blsSign, //aláírás
  blsVerify, //verifikáció
  blsCreateProof, //proof létrehozás
  blsVerifyProof, //proof verifikáció
} from "@mattrglobal/bbs-signatures";

async function main() {

    //Generate a new key pair
    const keyPair = await generateBls12381G2KeyPair();

    //Set of messages we wish to sign
    const messages = [ //itt most 2 darab üzenet van
        Uint8Array.from(Buffer.from("message1", "utf-8")),
        Uint8Array.from(Buffer.from("message2", "utf-8")),
    ];

    //Create the signature
    const signature = await blsSign({
        keyPair,
        messages: messages,
    });
    console.log(signature instanceof Uint8Array);
    

    //Verify the signature
    const isVerified = await blsVerify({
        publicKey: keyPair.publicKey,
        messages: messages,
        signature,
    });
    console.log(isVerified)
     console.log(isVerified instanceof Uint8Array);

    //Derive a proof from the signature revealing the first message
        const proof = await blsCreateProof({
        signature,
        publicKey: keyPair.publicKey,
        messages,
        nonce: Uint8Array.from(Buffer.from("nonce", "utf8")),
        revealed: [0], //csak a 0 indexű üzenetet fedem fel, ami itt a "message1"
    });
    console.log(proof instanceof Uint8Array);

    //Verify the created proof
    const isProofVerified = await blsVerifyProof({
        proof,
        publicKey: keyPair.publicKey,
        messages: messages.slice(0, 1),  //Csak a nulladik indexű elem van benne a messages-ben. 
        nonce: Uint8Array.from(Buffer.from("nonce", "utf8")),
    });
    console.log(proof instanceof Uint8Array);

      // --- Summary ---
        //console.log("\n=== SUMMARY ===");
        //console.log("Keypair generation: OK");
        //console.log("Signing:            OK");
        //console.log("Verification:       ", proof ? "PASS" : "FAIL");
        //console.log("Selective disclosure:", isProofVerified ? "PASS" : "FAIL");
    
}
main().catch();