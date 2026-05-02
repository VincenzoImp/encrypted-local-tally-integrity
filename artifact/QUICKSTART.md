# Quickstart

## Runtime

- Node `22.x`
- Yarn `1.x`

## Install

```bash
cd artifact
nvm use
yarn install
```

## Validate

```bash
yarn validate
```

This runs:

1. `yarn circuits:build`
2. the Hardhat contract test suite
3. a full replay of the example encrypted-local-tally election scenario

To run only the end-to-end scenario replay, use:

```bash
yarn replay
```

## Inspect Outputs

- `logs/contracts-test.log`
- `logs/replay.log`
- `logs/replay-summary.json`
- `logs/validation-summary.json`

## What The Replay Does

The bundled replay:

1. generates an encryption keypair
2. splits the decryption key into threshold shares
3. proves that the registered 2-of-3 trustee set is consistent with the
   election public key
4. deploys the verifier contracts and bulletin-board contract
5. registers the authorities and trustees from `scenarios/example-election.json`
6. encrypts each local tally
7. generates a Groth16 proof for each encrypted tally
8. signs each submission transcript and submits it on-chain
9. reconstructs the aggregate from the public transcript and checks that it
   matches the contract-maintained aggregate
10. generates a proof for each trustee share and submits the share on-chain
11. recovers the final tally only
