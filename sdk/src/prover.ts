/**
 * Client-side Groth16 proving for the Agent Passport circuit.
 *
 * Everything here runs where the secrets live — the user's browser or device.
 * `privateKey` and `balance` never leave; only the proof + public inputs do.
 * Works in Node (artifact = filesystem path) and the browser (artifact = URL
 * or `Uint8Array`), since that's exactly what snarkjs accepts.
 */
import * as snarkjs from "snarkjs";
import type { Groth16Proof } from "../bindings/src/index.js";

/** A snarkjs artifact: a path (Node), a URL (browser), or raw bytes. */
export type Artifact = string | Uint8Array;

export interface PassportArtifacts {
  /** Compiled circuit witness generator: `agent_passport_js/agent_passport.wasm`. */
  wasm: Artifact;
  /** Proving key: `agent_passport_final.zkey`. */
  zkey: Artifact;
  /** Optional helper circuit to derive registryRoot + nullifierHash from secrets. */
  witnessWasm?: Artifact;
  /** Optional verification key for an off-chain sanity check before submitting. */
  vk?: object;
}

/** The four public inputs, in the exact order the circuit (and contract) expect. */
export interface PublicInputs {
  registryRoot: string;
  nullifierHash: string;
  agentId: string;
  spendCap: string;
}

/** Private + public witness for `agent_passport.circom`. All values are decimal strings. */
export interface PassportWitness extends PublicInputs {
  privateKey: string;
  balance: string;
  pathElements: string[];
  pathIndices: string;
}

/** Merkle membership proof returned by an identity registry. */
export interface RegistryMerkleProof {
  /** Zero-based leaf position in the registry tree. */
  leafIndex: bigint | number | string;
  /** Sibling node at each level, from leaf level upward. */
  pathElements: readonly (bigint | number | string)[];
}

const normalizeLeafIndex = (
  leafIndex: RegistryMerkleProof["leafIndex"],
  levels: number,
): bigint => {
  if (!Number.isInteger(levels) || levels <= 0 || levels > 52) {
    throw new Error("levels must be an integer between 1 and 52");
  }
  if (typeof leafIndex === "number" && !Number.isSafeInteger(leafIndex)) {
    throw new Error("leafIndex number must be a safe integer");
  }
  const index = BigInt(leafIndex);
  const capacity = 1n << BigInt(levels);
  if (index < 0n || index >= capacity) {
    throw new Error(`leafIndex must be in [0, ${capacity})`);
  }
  return index;
};

/**
 * Convert a registry membership proof into the circuit witness shape.
 *
 * MerkleProof uses Num2Bits(levels), so pathIndices is the zero-based leaf
 * index encoded as one integer; bit 0 selects the leaf-level direction, bit 1
 * the next level, and so on. A 1 bit means the current node is the right child.
 */
export function merkleWitnessFromRegistryProof(
  proof: RegistryMerkleProof,
  levels = 20,
): Pick<PassportWitness, "pathElements" | "pathIndices"> {
  const leafIndex = normalizeLeafIndex(proof.leafIndex, levels);
  if (proof.pathElements.length !== levels) {
    throw new Error(
      `expected ${levels} Merkle siblings, got ${proof.pathElements.length}`,
    );
  }
  const pathElements = proof.pathElements.map((value, level) => {
    if (typeof value === "number" && !Number.isSafeInteger(value)) {
      throw new Error(`pathElements[${level}] number must be a safe integer`);
    }
    const field = BigInt(value);
    if (field < 0n) {
      throw new Error(`pathElements[${level}] must be non-negative`);
    }
    return field.toString();
  });
  return { pathElements, pathIndices: leafIndex.toString() };
}

/**
 * Derive the sibling path from concrete registry tree levels.
 *
 * treeLevels[0] contains leaves, treeLevels[1] their parents, etc. Each row
 * must include the sibling node selected by leafIndex at that level.
 */
export function merkleWitnessFromTreeLevels(
  treeLevels: readonly (readonly (bigint | number | string)[])[],
  leafIndex: bigint | number | string,
  levels = 20,
): Pick<PassportWitness, "pathElements" | "pathIndices"> {
  const index = normalizeLeafIndex(leafIndex, levels);
  if (treeLevels.length < levels) {
    throw new Error(`expected at least ${levels} tree levels, got ${treeLevels.length}`);
  }

  let cursor = index;
  const siblings: (bigint | number | string)[] = [];
  for (let level = 0; level < levels; level++) {
    const siblingIndex = Number(cursor ^ 1n);
    const sibling = treeLevels[level]?.[siblingIndex];
    if (sibling === undefined) {
      throw new Error(
        `missing Merkle sibling at level ${level}, index ${siblingIndex}`,
      );
    }
    siblings.push(sibling);
    cursor >>= 1n;
  }

  return merkleWitnessFromRegistryProof(
    { leafIndex: index, pathElements: siblings },
    levels,
  );
}

/** A proof packaged for the AgentPassportValidator contract. */
export interface SorobanProof {
  /** Ready for the typed contract client (`Groth16Proof`). */
  proof: Groth16Proof;
  /** Hex form (no `0x`) — handy for `stellar contract invoke` / debugging. */
  proofHex: { a: string; b: string; c: string };
  /** `[registryRoot, nullifierHash, agentId, spendCap]` as decimal strings. */
  publicInputs: string[];
  /** Raw snarkjs outputs, in case you want to re-verify off-chain. */
  raw: { proof: snarkjs.Groth16Proof; publicSignals: string[] };
}

const FIELD_HEX = 64; // 32-byte BE field element.

const be32 = (dec: string | bigint): string => {
  const h = BigInt(dec).toString(16);
  if (h.length > FIELD_HEX) throw new Error(`field element overflow: ${dec}`);
  return h.padStart(FIELD_HEX, "0");
};

const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

// Soroban byte layout: G1 (64B) = x||y; G2 (128B) = x.c1||x.c0||y.c1||y.c0.
const g1Hex = (p: string[]): string => be32(p[0]) + be32(p[1]);
const g2Hex = (p: string[][]): string =>
  be32(p[0][1]) + be32(p[0][0]) + be32(p[1][1]) + be32(p[1][0]);

/**
 * Convert a snarkjs proof into the AgentPassportValidator's argument format.
 * Pure / synchronous — no proving, just re-encoding.
 */
export function toSorobanProof(
  proof: snarkjs.Groth16Proof,
  publicSignals: string[],
): SorobanProof {
  const a = g1Hex(proof.pi_a);
  const b = g2Hex(proof.pi_b);
  const c = g1Hex(proof.pi_c);
  return {
    proof: {
      a: Buffer.from(hexToBytes(a)),
      b: Buffer.from(hexToBytes(b)),
      c: Buffer.from(hexToBytes(c)),
    },
    proofHex: { a, b, c },
    publicInputs: publicSignals.map(String),
    raw: { proof, publicSignals },
  };
}

/**
 * Derive `registryRoot` + `nullifierHash` from the private witness using the
 * helper circuit, so callers don't have to reimplement Poseidon2 off-circuit.
 * Requires `artifacts.witnessWasm`.
 */
export async function derivePublicInputs(
  secret: { privateKey: string; agentId: string; pathElements: string[]; pathIndices: string },
  witnessWasm: Artifact,
): Promise<{ registryRoot: string; nullifierHash: string }> {
  const { type, data } = await snarkjs.wtns.calculate(secret, witnessWasm as any, undefined as any);
  const w = await snarkjs.wtns.exportJson({ type, data } as any);
  return { registryRoot: w[1].toString(), nullifierHash: w[2].toString() };
}

/**
 * Generate a passport proof from a full witness and package it for Soroban.
 * If `artifacts.vk` is supplied, the proof is sanity-checked off-chain first.
 */
export async function generatePassportProof(
  witness: PassportWitness,
  artifacts: PassportArtifacts,
): Promise<SorobanProof> {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witness,
    artifacts.wasm as any,
    artifacts.zkey as any,
  );

  if (artifacts.vk) {
    const ok = await snarkjs.groth16.verify(artifacts.vk, publicSignals, proof);
    if (!ok) throw new Error("off-chain verification failed — refusing to submit");
  }

  return toSorobanProof(proof, publicSignals);
}
