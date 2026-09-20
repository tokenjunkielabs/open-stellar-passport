import { describe, expect, it } from "vitest";
import type { Groth16Proof as SnarkProof } from "snarkjs";
import {
  merkleWitnessFromRegistryProof,
  merkleWitnessFromTreeLevels,
  toSorobanProof,
} from "./prover";

const field = (value: number) => value.toString();

const sampleProof = {
  pi_a: [field(1), field(2)],
  pi_b: [
    [field(3), field(4)],
    [field(5), field(6)],
  ],
  pi_c: [field(7), field(8)],
} as SnarkProof;

const word = (value: number) => value.toString(16).padStart(64, "0");

describe("toSorobanProof", () => {
  it("encodes G1 and G2 coordinates in the contract byte order", () => {
    const encoded = toSorobanProof(sampleProof, ["11", "12", "13", "14"]);

    expect(encoded.proofHex).toEqual({
      a: word(1) + word(2),
      b: word(4) + word(3) + word(6) + word(5),
      c: word(7) + word(8),
    });
    expect(Buffer.from(encoded.proof.a).toString("hex")).toBe(
      encoded.proofHex.a,
    );
    expect(Buffer.from(encoded.proof.b).toString("hex")).toBe(
      encoded.proofHex.b,
    );
    expect(Buffer.from(encoded.proof.c).toString("hex")).toBe(
      encoded.proofHex.c,
    );
    expect(encoded.publicInputs).toEqual(["11", "12", "13", "14"]);
  });

  it("rejects field elements wider than 32 bytes", () => {
    const overflowingProof = {
      ...sampleProof,
      pi_a: [`0x1${"0".repeat(64)}`, field(2)],
    } as SnarkProof;

    expect(() => toSorobanProof(overflowingProof, [])).toThrow(
      /field element overflow/i,
    );
  });
});


describe("registry Merkle witnesses", () => {
  it("encodes a non-zero leaf index with Num2Bits-compatible direction bits", () => {
    const witness = merkleWitnessFromRegistryProof(
      {
        leafIndex: 5n, // binary 101: right, left, right from leaf upward
        pathElements: ["11", "22", "33"],
      },
      3,
    );

    expect(witness).toEqual({
      pathElements: ["11", "22", "33"],
      pathIndices: "5",
    });
  });

  it("derives sibling elements from the member's actual tree position", () => {
    const witness = merkleWitnessFromTreeLevels(
      [
        ["100", "101", "102", "103", "104", "105", "106", "107"],
        ["200", "201", "202", "203"],
        ["300", "301"],
      ],
      5n,
      3,
    );

    expect(witness).toEqual({
      pathElements: ["104", "203", "300"],
      pathIndices: "5",
    });
  });
});
