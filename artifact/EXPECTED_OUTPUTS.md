# Expected Outputs

After `yarn validate`, the canonical summary is written to:

- `logs/validation-summary.json`

The replay summary is written to:

- `logs/replay-summary.json`

For the bundled example scenario, the expected final tally is:

- `Alice = 35`
- `Bob = 29`

and the expected winner set is:

- `Alice`

The replay also confirms that:

- all encrypted local tallies were accepted
- all Groth16 proofs verified
- all submission signatures verified
- all checked decryption-share proofs verified
- local tallies were never published in clear
- the aggregate was reconstructed from the stored ciphertext transcript
- the contract-maintained aggregate matches the transcript-derived aggregate
- the trustee registry, threshold, and decryption-share transcript were
  anchored and verified on-chain
- the election ends in the `ReadyForDecryption` phase before final off-chain
  recovery of the aggregate tally
