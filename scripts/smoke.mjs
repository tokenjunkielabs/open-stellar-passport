// Phase 0 smoke test: build a valid witness, generate a Groth16 proof, and
// verify it off-chain with snarkjs. Proves the full proving pipeline works
// end-to-end before we bake the VK into the Soroban verifier.
import * as snarkjs from "snarkjs";
import { readFileSync } from "node:fs";

const B = "build";

// Random-ish field element helper (well within BN254 scalar field).
const rnd = () =>
  BigInt(
    "0x" +
      [...crypto.getRandomValues(new Uint8Array(28))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
  );

async function main() {
  const privateKey = rnd().toString();
  const agentId = "42"; // pretend Stellar-8004 agent id
  const balance = "1000000000"; // hidden real balance
  const spendCap = "500000000"; // passport vouches for <= this; balance >= it
  // Exercise a real non-zero position: 5 = 0b101, consumed LSB-first by Num2Bits.
  const leafIndex = 5n;
  const pathIndices = leafIndex.toString();
  const pathElements = Array.from({ length: 20 }, () => rnd().toString());

  // 1. Use the helper circuit to compute the matching registryRoot + nullifierHash.
  await snarkjs.wtns.calculate(
    { privateKey, agentId, pathElements, pathIndices },
    `${B}/passport_witness_js/passport_witness.wasm`,
    `${B}/pw.wtns`,
  );
  const w = await snarkjs.wtns.exportJson(`${B}/pw.wtns`);
  // witness layout: [1, registryRoot, nullifierHash, publicKey, ...]
  const registryRoot = w[1].toString();
  const nullifierHash = w[2].toString();
  console.log("computed registryRoot :", registryRoot);
  console.log("computed nullifierHash:", nullifierHash);

  // 2. Full input for the real AgentPassport circuit.
  const input = {
    registryRoot,
    nullifierHash,
    agentId,
    spendCap,
    privateKey,
    balance,
    pathElements,
    pathIndices,
  };

  // 3. Generate the Groth16 proof.
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    `${B}/agent_passport_js/agent_passport.wasm`,
    `${B}/agent_passport_final.zkey`,
  );

  // 4. Verify off-chain.
  const vk = JSON.parse(readFileSync(`${B}/verification_key.json`, "utf8"));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);

  console.log(
    "\npublicSignals (order = [registryRoot, nullifierHash, agentId, spendCap]):",
  );
  console.log(publicSignals);
  console.log("\n==> PROOF VALID:", ok);
  process.exit(ok ? 0 : 1);
}

main().catch((error) => {
  console.error(
    "smoke failed:",
    error instanceof Error ? error.message : error,
  );
  process.exit(1);
});
