/**
 * The whole Agent Passport pipeline, in the browser:
 *   fresh secret witness  →  Groth16 proof (snarkjs/WASM)  →  live on-chain
 *   verification against the deployed Soroban validator.
 *
 * `privateKey` and `balance` are generated and consumed here; only the proof
 * and its four public inputs are ever sent to the network.
 */
import * as snarkjs from "snarkjs";
import { Buffer } from "buffer";
import { Client, Errors } from "./validatorClient";
import { TESTNET_CONFIG } from "./testnetConfig";

export const CONTRACTS = {
  validator: TESTNET_CONFIG.validatorContractId,
  verifier: TESTNET_CONFIG.verifierContractId,
};

// Prefix with Vite's base URL so assets resolve under a sub-path deploy
// (e.g. GitHub Pages at /open-stellar-passport/).
const BASE = import.meta.env.BASE_URL;
const ART = {
  circuit: `${BASE}zk/agent_passport.wasm`,
  zkey: `${BASE}zk/agent_passport_final.zkey`,
  witness: `${BASE}zk/passport_witness.wasm`,
  vk: `${BASE}zk/verification_key.json`,
};

export interface SorobanProof {
  proof: { a: Buffer; b: Buffer; c: Buffer };
  proofHex: { a: string; b: string; c: string };
  publicInputs: string[]; // [registryRoot, nullifierHash, agentId, spendCap]
}

export interface MintedProof extends SorobanProof {
  agentId: string;
  spendCap: string;
  registryRoot: string;
  nullifierHash: string;
  raw: snarkjs.Groth16Proof;
  offChainValid: boolean;
  provingMs: number;
}

export interface RegistryMerkleProof {
  /** Zero-based member position; Num2Bits consumes its bits leaf-level first. */
  leafIndex: bigint | number | string;
  /** Registry siblings ordered from leaf level upward. */
  pathElements: readonly (bigint | number | string)[];
}

export interface OnChainResult {
  ok: boolean;
  attestation?: {
    agent_id: string;
    nullifier: string;
    registry_root: string;
    spend_cap: string;
    ledger: number;
  };
  error?: string;
}

// ------------------------------------------------------------------ helpers

const rndField = () =>
  BigInt(
    "0x" +
      [...crypto.getRandomValues(new Uint8Array(28))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
  ).toString();

/** A friendly, displayable agent id (still a valid field element). */
const rndAgentId = () =>
  BigInt(
    "0x" +
      [...crypto.getRandomValues(new Uint8Array(5))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
  ).toString();

const be32 = (dec: string | bigint) => {
  const h = BigInt(dec).toString(16);
  if (h.length > 64) throw new Error("field element overflow");
  return h.padStart(64, "0");
};
const g1 = (p: string[]) => be32(p[0]) + be32(p[1]);
const g2 = (p: string[][]) =>
  be32(p[0][1]) + be32(p[0][0]) + be32(p[1][1]) + be32(p[1][0]);
const buf = (hex: string) => Buffer.from(hex, "hex");

const fetchBytes = async (url: string) =>
  new Uint8Array(await (await fetch(url)).arrayBuffer());

function toSoroban(
  raw: snarkjs.Groth16Proof,
  publicSignals: string[],
): SorobanProof {
  const a = g1(raw.pi_a),
    b = g2(raw.pi_b),
    c = g1(raw.pi_c);
  return {
    proof: { a: buf(a), b: buf(b), c: buf(c) },
    proofHex: { a, b, c },
    publicInputs: publicSignals.map(String),
  };
}

function errName(code: number): string {
  return (
    (Errors as Record<number, { message: string }>)[code]?.message ??
    `Error #${code}`
  );
}

export function parseContractError(e: unknown): string {
  const s = String((e as Error)?.message ?? e);
  const m = s.match(/Error\(Contract,\s*#(\d+)\)/) ?? s.match(/#(\d+)/);
  if (m) return errName(Number(m[1]));
  return s.length > 140 ? s.slice(0, 140) + "…" : s;
}

function client(publicKey = TESTNET_CONFIG.viewerPublicKey) {
  return new Client({
    contractId: CONTRACTS.validator,
    networkPassphrase: TESTNET_CONFIG.networkPassphrase,
    rpcUrl: TESTNET_CONFIG.rpcUrl,
    publicKey,
    allowHttp: true,
  });
}

// ------------------------------------------------------------------ pipeline

/**
 * Generate a brand-new passport: random owner secret + agent id, derive the
 * public root/nullifier via the helper circuit, then prove the full circuit.
 */
export async function mintPassport(
  spendCap: string,
  registryProof?: RegistryMerkleProof,
): Promise<MintedProof> {
  const privateKey = rndField();
  const agentId = rndAgentId();
  const balance = (BigInt(spendCap) + BigInt(rndAgentId())).toString(); // > cap, hidden
  const levels = 20;
  const maxLeaves = 1n << BigInt(levels);
  const leafIndex = registryProof
    ? BigInt(registryProof.leafIndex)
    : (BigInt(rndAgentId()) % (maxLeaves - 1n)) + 1n;
  if (leafIndex < 0n || leafIndex >= maxLeaves) {
    throw new Error(`registry leaf index must be in [0, ${maxLeaves})`);
  }
  const pathElements = (registryProof?.pathElements ??
    Array.from({ length: levels }, rndField)).map(String);
  if (pathElements.length !== levels) {
    throw new Error(`expected ${levels} Merkle siblings, got ${pathElements.length}`);
  }
  const pathIndices = leafIndex.toString();

  const witnessWasm = await fetchBytes(ART.witness);
  const o = { type: "mem" } as object;
  await snarkjs.wtns.calculate(
    { privateKey, agentId, pathElements, pathIndices },
    witnessWasm,
    o,
  );
  const w = await snarkjs.wtns.exportJson(o);
  const registryRoot = w[1].toString();
  const nullifierHash = w[2].toString();

  const [circuitWasm, zkey] = await Promise.all([
    fetchBytes(ART.circuit),
    fetchBytes(ART.zkey),
  ]);
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

  const t0 = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    circuitWasm,
    zkey,
  );
  const provingMs = Math.round(performance.now() - t0);

  const vk = await (await fetch(ART.vk)).json();
  const offChainValid = await snarkjs.groth16.verify(vk, publicSignals, proof);

  return {
    ...toSoroban(proof, publicSignals),
    agentId,
    spendCap,
    registryRoot,
    nullifierHash,
    raw: proof,
    offChainValid,
    provingMs,
  };
}

/** Live on-chain verification via read-only simulation (no wallet, no persist). */
export async function verifyOnChain(p: SorobanProof): Promise<OnChainResult> {
  try {
    const tx = await client().verify_and_register({
      proof: p.proof,
      public_inputs: p.publicInputs.map((s) => BigInt(s)),
    });
    const r = tx.result as unknown as {
      isOk: () => boolean;
      unwrap: () => {
        agent_id: bigint;
        nullifier: bigint;
        registry_root: bigint;
        spend_cap: bigint;
        ledger: number;
      };
      unwrapErr: () => { message?: string };
    };
    if (r.isOk()) {
      const a = r.unwrap();
      return {
        ok: true,
        attestation: {
          ...a,
          agent_id: String(a.agent_id),
          nullifier: String(a.nullifier),
          registry_root: String(a.registry_root),
          spend_cap: String(a.spend_cap),
          ledger: Number(a.ledger),
        },
      };
    }
    return { ok: false, error: r.unwrapErr()?.message ?? "InvalidProof" };
  } catch (e) {
    return { ok: false, error: parseContractError(e) };
  }
}

/** Persist the passport on-chain (needs a Freighter signer). Returns tx hash. */
export async function commitOnChain(
  p: SorobanProof,
  publicKey: string,
  signTransaction: (
    xdr: string,
    opts?: object,
  ) => Promise<{ signedTxXdr: string }>,
): Promise<{ ok: boolean; hash?: string; error?: string }> {
  try {
    const tx = await client(publicKey).verify_and_register({
      proof: p.proof,
      public_inputs: p.publicInputs.map((s) => BigInt(s)),
    });
    const sent = await tx.signAndSend({
      // adapt Freighter's signer to the contract client's expected shape
      signTransaction: async (xdr: string, opts?: object) =>
        signTransaction(xdr, opts),
    });
    return {
      ok: true,
      hash: (sent as { sendTransactionResponse?: { hash?: string } })
        .sendTransactionResponse?.hash,
    };
  } catch (e) {
    return { ok: false, error: parseContractError(e) };
  }
}

export async function isRegistered(agentId: string): Promise<boolean> {
  const tx = await client().is_registered({ agent_id: BigInt(agentId) });
  return tx.result;
}

export async function getPassport(
  agentId: string,
): Promise<OnChainResult["attestation"] | undefined> {
  const tx = await client().get_passport({ agent_id: BigInt(agentId) });
  const a = tx.result;
  if (!a) return undefined;
  return {
    agent_id: String(a.agent_id),
    nullifier: String(a.nullifier),
    registry_root: String(a.registry_root),
    spend_cap: String(a.spend_cap),
    ledger: Number(a.ledger),
  };
}

export function evaluatePaymentAuthorization(
  passport:
    | Pick<NonNullable<OnChainResult["attestation"]>, "spend_cap">
    | undefined,
  amount: string,
): { authorized: boolean; reason: string; cap?: string } {
  if (!passport)
    return { authorized: false, reason: "No passport — agent not verified" };

  if (!/^[0-9]+$/.test(amount) || BigInt(amount) <= 0n) {
    return {
      authorized: false,
      cap: passport.spend_cap,
      reason: "Invalid payment amount",
    };
  }

  const ok = BigInt(passport.spend_cap) >= BigInt(amount);
  return {
    authorized: ok,
    cap: passport.spend_cap,
    reason: ok ? "Within proven spend cap" : "Exceeds proven spend cap",
  };
}

/**
 * The x402 settle gate: an agent may pay `amount` iff it holds a passport
 * whose proven (hidden) spend cap covers it. Pure on-chain reads.
 */
export async function authorizePayment(
  agentId: string,
  amount: string,
): Promise<{ authorized: boolean; reason: string; cap?: string }> {
  const passport = await getPassport(agentId);
  return evaluatePaymentAuthorization(passport, amount);
}

/**
 * Replay demo: a *real* previously-spent proof (agent 42, committed earlier).
 * The chain rejects it with NullifierUsed — anti-replay, live.
 */
export async function replaySpentProof(): Promise<OnChainResult> {
  const [hex, pub] = await Promise.all([
    fetch(`${BASE}zk/spent_proof.json`).then((r) => r.json()),
    fetch(`${BASE}zk/spent_public.json`).then((r) => r.json()),
  ]);
  const p: SorobanProof = {
    proof: { a: buf(hex.a), b: buf(hex.b), c: buf(hex.c) },
    proofHex: hex,
    publicInputs: pub,
  };
  return verifyOnChain(p);
}
