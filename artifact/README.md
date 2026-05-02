# Reproducible Artifact

This artifact implements a protocol for federated elections with private local
tallies.

It does not implement a full ballot-level e-voting stack. Instead, it
implements the integrity layer needed once local voting is already secret and
local counting is assumed correct:

- each local authority performs secret local voting and correct local counting
  off-chain;
- each authority encrypts its local tally vector;
- each authority submits the encrypted vector together with a Groth16 proof
  that the hidden tally is structurally valid and sums to the authority's
  electorate size;
- the contract accepts exactly one encrypted submission per authorized
  authority and maintains the homomorphic aggregate on-chain;
- the contract also anchors a trustee set consistent with the election public
  key, the decryption threshold, and the partial-decryption transcript;
- the public transcript fixes the full set of accepted local contributions;
- only the global aggregate is decrypted at the end.

## What It Demonstrates

- authorization of registered authorities only
- one encrypted tally submission per authority
- on-chain Groth16 verification of local-tally well-formedness
- contract-level signature binding of accepted submissions to election state
- on-chain homomorphic aggregation updated from accepted ciphertext vectors
- on-chain verification that the instantiated trustee set is consistent with
  the election public key
- on-chain verification and recording of partial decryption shares
- threshold decryption of the final aggregate only
- replay-based recovery of the final tally from the verified on-chain opening
  transcript
- cancellation on expiry instead of partial-result finalization

## Quick Start

```bash
cd artifact
nvm use
yarn install
yarn validate
```

The validation command rebuilds the circuit artifacts if needed, runs the
contract test suite, and then replays a complete encrypted-local-tally election
from `scenarios/example-election.json`.

To execute only the end-to-end transcript replay, run `yarn replay`.

## Architecture

The artifact has three layers:

- `contracts/`
  - `ZKLocalTallyIntegrity.sol` registers authorities, starts an election,
    accepts encrypted tallies, updates the aggregate ciphertext, verifies the
    trustee setup, and records proof-checked trustee shares for final opening
  - generated verifier contracts validate the three Groth16 statements
- `circuits/`
  - `EncryptedLocalTally.circom` proves that the hidden local tally is in
    range, sums to the registered electorate size, and matches the published
    ciphertexts
  - `TrusteeRegistry2of3.circom` proves that the artifact's 2-of-3 trustee set
    is consistent with the published election public key
  - `PartialDecryptionShare.circom` proves that a submitted trustee share
    matches the contract-maintained aggregate ciphertext
- `scripts/`
  - `buildCircuits.mjs` compiles all circuits and generates the verifier
    contracts from the packaged local `circuits/ptau/pot15.ptau`
  - `replayScenario.js` runs the full end-to-end workflow and reconstructs both
    the aggregate and the opening step from the on-chain transcript
  - `runValidation.mjs` orchestrates build, tests, replay, and summary checks

## Security Story

The artifact is designed to address the attacks that matter in federated tally
aggregation:

- a central coordinator cannot omit an accepted authority tally from the
  transcript
- authorities do not see each other's local tallies, even after the election
- malformed encrypted submissions are blocked by the proof gate
- accepted submissions are bound to the current election state by authority
  signatures
- the trustee set cannot be switched to an inconsistent registry at election
  start
- invalid partial decryptions are rejected before entering the opening
  transcript
- the replay audits aggregation from the stored ciphertext transcript rather
  than from local pre-submission state
- the trustee set, decryption threshold, and opening transcript are fixed in
  election state
- only the global tally is opened

The remaining explicit limitation is that the proof establishes
well-formedness, not truthfulness. A fully corrupted local committee that
chooses a false but plausible tally remains outside the artifact assumptions.
