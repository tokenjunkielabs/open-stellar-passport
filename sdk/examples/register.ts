/**
 * End-to-end example: prove a passport client-side and mint it on testnet.
 *
 *   STELLAR_SECRET=S... node --loader ts-node/esm examples/register.ts
 *
 * Uses the circuit artifacts produced by the repo's Phase 0 build (see README).
 */
import { Keypair } from "@stellar/stellar-sdk";
import { basicNodeSigner } from "@stellar/stellar-sdk/contract";
import { randomBytes } from "node:crypto";
import {
  AgentPassport,
  derivePublicInputs,
  merkleWitnessFromRegistryProof,
  type PassportWitness,
} from "../src/index.js";

const B = "../build"; // circuit artifacts from `npm run build` at repo root

const rndField = () => BigInt("0x" + randomBytes(28).toString("hex")).toString();

async function main() {
  const secret = process.env.STELLAR_SECRET;
  if (!secret) throw new Error("set STELLAR_SECRET to a funded testnet secret key");
  const kp = Keypair.fromSecret(secret);
  const signer = basicNodeSigner(kp, "Test SDF Network ; September 2015");

  // --- assemble a passport witness (secrets live only here) ---
  const privateKey = rndField();
  const agentId = "42";
  // Synthetic demo registry proof at a non-zero member position. Production
  // callers pass the registry's real sibling list + zero-based leaf index.
  const { pathIndices, pathElements } = merkleWitnessFromRegistryProof({
    leafIndex: 5n,
    pathElements: Array.from({ length: 20 }, rndField),
  });

  const artifacts = {
    wasm: `${B}/agent_passport_js/agent_passport.wasm`,
    zkey: `${B}/agent_passport_final.zkey`,
    witnessWasm: `${B}/passport_witness_js/passport_witness.wasm`,
  };

  // derive the public root + nullifier from the secret witness
  const { registryRoot, nullifierHash } = await derivePublicInputs(
    { privateKey, agentId, pathElements, pathIndices },
    artifacts.witnessWasm,
  );

  const witness: PassportWitness = {
    registryRoot,
    nullifierHash,
    agentId,
    spendCap: "500000000",
    privateKey,
    balance: "1000000000", // proven >= spendCap, never revealed
    pathElements,
    pathIndices,
  };

  const sdk = new AgentPassport({
    rpcUrl: "https://soroban-testnet.stellar.org",
    artifacts,
    publicKey: kp.publicKey(),
    signTransaction: signer.signTransaction,
  });

  console.log("proving client-side…");
  const proof = await sdk.prove(witness);
  console.log("public inputs:", proof.publicInputs);

  console.log("registering on-chain…");
  const attestation = await sdk.register(proof);
  console.log("✅ passport minted:", attestation);

  console.log("is_registered:", await sdk.isRegistered(agentId));
  console.log("authorizePayment(400000000):", await sdk.authorizePayment(agentId, "400000000"));
  console.log("authorizePayment(600000000):", await sdk.authorizePayment(agentId, "600000000"));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
