// Generate a Groth16 proof and convert it to the Soroban verifier's arg format.
// Writes build/arg_proof.json and build/arg_public.json ready for `stellar contract invoke`.
import * as snarkjs from "snarkjs";
import { readFileSync, writeFileSync } from "node:fs";

const B = "build";
const rnd = () =>
  BigInt(
    "0x" +
      [...crypto.getRandomValues(new Uint8Array(28))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
  );

async function main() {
  // --- sample passport inputs ---
  const privateKey = rnd().toString();
  const agentId = "42";
  const balance = "1000000000";
  const spendCap = "500000000";
  const leafIndex = 5n; // non-zero registry member; Num2Bits reads this LSB-first
  const pathIndices = leafIndex.toString();
  const pathElements = Array.from({ length: 20 }, () => rnd().toString());

  // 1. helper circuit -> matching registryRoot + nullifierHash
  await snarkjs.wtns.calculate(
    { privateKey, agentId, pathElements, pathIndices },
    `${B}/passport_witness_js/passport_witness.wasm`,
    `${B}/pw.wtns`,
  );
  const w = await snarkjs.wtns.exportJson(`${B}/pw.wtns`);
  const registryRoot = w[1].toString();
  const nullifierHash = w[2].toString();

  // 2. real proof
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
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    `${B}/agent_passport_js/agent_passport.wasm`,
    `${B}/agent_passport_final.zkey`,
  );

  // 3. off-chain sanity check
  const vk = JSON.parse(readFileSync(`${B}/verification_key.json`, "utf8"));
  console.log(
    "off-chain verify:",
    await snarkjs.groth16.verify(vk, publicSignals, proof),
  );
  writeFileSync(`${B}/proof.json`, JSON.stringify(proof, null, 2));
  writeFileSync(`${B}/public.json`, JSON.stringify(publicSignals, null, 2));

  // 4. convert to Soroban byte layout
  //    G1 (64B): x||y          G2 (128B): x.c1||x.c0||y.c1||y.c0   (32B BE each)
  const be32 = (dec) => {
    const h = BigInt(dec).toString(16);
    if (h.length > 64) throw new Error("field element overflow");
    return h.padStart(64, "0");
  };
  const g1 = (p) => be32(p[0]) + be32(p[1]);
  const g2 = (p) =>
    be32(p[0][1]) + be32(p[0][0]) + be32(p[1][1]) + be32(p[1][0]);

  const argProof = { a: g1(proof.pi_a), b: g2(proof.pi_b), c: g1(proof.pi_c) };
  writeFileSync(`${B}/arg_proof.json`, JSON.stringify(argProof));
  writeFileSync(
    `${B}/arg_public.json`,
    JSON.stringify(publicSignals.map(String)),
  );

  console.log(
    "publicSignals [registryRoot, nullifierHash, agentId, spendCap]:",
  );
  console.log(publicSignals);
  console.log("wrote build/arg_proof.json + build/arg_public.json");
}

main().catch((error) => {
  console.error(
    "gen-proof failed:",
    error instanceof Error ? error.message : error,
  );
  process.exit(1);
});
