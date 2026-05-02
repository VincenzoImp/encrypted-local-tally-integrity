# Encrypted Local Tally Integrity

This repository is the public Koine submission package for federated election
integrity with encrypted local tallies.

The package is intentionally narrow:

- `paper/` contains the Koine article in the official template
- `artifact/` contains a reproducible no-frontend artifact

The protocol implemented here is a blockchain-assisted integrity layer for
federated elections with private local tallies. Each local authority computes
its tally off-chain, encrypts that tally, and submits only the encrypted
vector together with a Groth16 proof that the hidden tally is well formed and
matches the authority's public electorate size. The contract accepts one
encrypted submission per authorized authority, maintains the homomorphic
aggregate on-chain, and the global tally is recovered only at the end through
threshold decryption. Local tallies are never revealed.

## Quick Start

Paper:

```bash
cd paper
pdflatex article
bibtex article
pdflatex article
pdflatex article
```

Artifact:

```bash
cd artifact
nvm use
yarn install
yarn validate
```

## Authors

- Vincenzo Imperati, Sapienza University of Rome, Italy,
  `imperati@di.uniroma1.it`,
  ORCID: `0009-0001-9437-1384`
- Lorenzo Camilli, Sapienza University of Rome, Italy,
  `camilli.1845956@studenti.uniroma1.it`,
  ORCID: `0009-0000-5122-5515`
- Raffaele Ruggeri, Sapienza University of Rome, Italy,
  `ruggeri.1934646@studenti.uniroma1.it`,
  ORCID: `0009-0000-5833-8424`

## Editorial Positioning

This package presents a paper and artifact for federated tally integrity under
the following assumptions:

- local vote secrecy is handled within each authority and is out of scope
- local counting is assumed correct
- the integrity problem is the final aggregation of all local tallies
- local tallies should not be exposed, even after the election
- blockchain is used as a bulletin board, proof gate, and transcript anchor
- zero-knowledge proofs are used to block malformed encrypted submissions and
  invalid opening transcripts
- only the global aggregate is opened at the end

## Current Artifact Shape

The artifact currently instantiates:

- two candidates
- three local authorities in the bundled replay
- curve-based additively homomorphic ElGamal-style encryption
- three Circom/Groth16 proofs: tally validity, trustee-set consistency, and
  partial decryption validity
- threshold decryption with proof-checked decryption shares accepted on-chain

The artifact is intentionally a research artifact rather than a deployment
product. It demonstrates the full workflow and its security motivation without
introducing a frontend.

## Validation Status

- paper: `paper/article.pdf`, validated as a 5-page Koine article
- artifact: validation passed on 2026-05-02; run `yarn validate` with the
  Node version declared in `artifact/.nvmrc`
- validation covers circuit generation, contract tests, and deterministic
  replay against `artifact/expected/replay-summary.expected.json`

## Citation

Artifact citation metadata is available in `artifact/CITATION.cff`.

## License

The artifact code is released under the MIT License; see `artifact/LICENSE`.
The paper is Koine submission material prepared for publication with the
submitted contribution.

## Public Repository

The paper and companion artifact are published at:

https://github.com/VincenzoImp/encrypted-local-tally-integrity
