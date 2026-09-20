// On-chain smoke test against the deployed AgentPassportValidator.
//   node --use-system-ca scripts/smoke-onchain.mjs
// (this machine's Node needs --use-system-ca for the Soroban RPC TLS cert)
import * as snarkjs from "snarkjs";
import fs from "node:fs";
import { Client } from "../sdk/bindings/dist/index.js";
import { testnetConfig } from "../config/testnet.mjs";

const B = new URL("../build/", import.meta.url);
const read = (f) => new Uint8Array(fs.readFileSync(new URL(f, B)));
const json = (f) => JSON.parse(fs.readFileSync(new URL(f, B)));
const rnd = () =>
  BigInt(
    "0x" +
      [...crypto.getRandomValues(new Uint8Array(28))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
  ).toString();
const be32 = (d) => {
  const h = BigInt(d).toString(16);
  if (h.length > 64) throw new Error("field element overflow");
  return h.padStart(64, "0");
};
const g1 = (p) => be32(p[0]) + be32(p[1]);
const g2 = (p) => be32(p[0][1]) + be32(p[0][0]) + be32(p[1][1]) + be32(p[1][0]);

const client = new Client({
  contractId: testnetConfig.validatorContractId,
  networkPassphrase: testnetConfig.networkPassphrase,
  rpcUrl: testnetConfig.rpcUrl,
  publicKey: testnetConfig.viewerPublicKey,
  allowHttp: true,
});

let pass = 0,
  fail = 0;
const check = (name, ok, extra = "") => {
  console.log(`${ok ? "  ✓" : "  ✗"} ${name}${extra ? " — " + extra : ""}`);
  ok ? pass++ : fail++;
};

async function main() {
  console.log("contract:", testnetConfig.validatorContractId);

  // 1) fresh proof -> on-chain verify (read-only simulation)
  const privateKey = rnd();
  const agentId = BigInt(
    "0x" +
      [...crypto.getRandomValues(new Uint8Array(5))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
  ).toString();
  const leafIndex = 5n; // non-zero registry member; direction bits are LSB-first
  const pathIndices = leafIndex.toString();
  const pathElements = Array.from({ length: 20 }, rnd);
  const o = { type: "mem" };
  await snarkjs.wtns.calculate(
    { privateKey, agentId, pathElements, pathIndices },
    read("passport_witness_js/passport_witness.wasm"),
    o,
  );
  const w = await snarkjs.wtns.exportJson(o);
  const t0 = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      registryRoot: w[1].toString(),
      nullifierHash: w[2].toString(),
      agentId,
      spendCap: "500000000",
      privateKey,
      balance: "1000000000",
      pathElements,
      pathIndices,
    },
    read("agent_passport_js/agent_passport.wasm"),
    read("agent_passport_final.zkey"),
  );
  const sorobanProof = {
    a: Buffer.from(g1(proof.pi_a), "hex"),
    b: Buffer.from(g2(proof.pi_b), "hex"),
    c: Buffer.from(g1(proof.pi_c), "hex"),
  };
  const tx = await client.verify_and_register({
    proof: sorobanProof,
    public_inputs: publicSignals.map((s) => BigInt(s)),
  });
  check(
    `fresh proof verifies on-chain (agent #${agentId})`,
    tx.result.isOk?.() === true,
    `${Math.round(performance.now() - t0)} ms`,
  );

  // 2) known-spent proof -> NullifierUsed
  const sp = json("arg_proof.json");
  const spub = json("arg_public.json");
  const rtx = await client.verify_and_register({
    proof: {
      a: Buffer.from(sp.a, "hex"),
      b: Buffer.from(sp.b, "hex"),
      c: Buffer.from(sp.c, "hex"),
    },
    public_inputs: spub.map((s) => BigInt(s)),
  });
  const err = rtx.result.isOk?.()
    ? ""
    : JSON.stringify(rtx.result.unwrapErr?.());
  check(
    "replay of a spent proof is rejected",
    !rtx.result.isOk?.() && /[Nn]ullifier/.test(err),
    err,
  );

  // 3) reads
  check(
    "is_registered(42) == true",
    (await client.is_registered({ agent_id: 42n })).result === true,
  );
  check(
    "get_passport(42) present",
    !!(await client.get_passport({ agent_id: 42n })).result,
  );

  console.log(
    `\n${fail === 0 ? "SMOKE OK" : "SMOKE FAILED"} — ${pass} passed, ${fail} failed`,
  );
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(
    "smoke-onchain failed:",
    error instanceof Error ? error.message : error,
  );
  process.exit(1);
});
