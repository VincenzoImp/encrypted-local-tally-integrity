# Paper Package

This folder contains the Koine paper source in the official template. It is
written as a standalone article on federated election integrity with private
local tallies. Local vote privacy and local counting stay outside the
protocol; the paper focuses on encrypted local tallies, proof-based
acceptance, transcript integrity, and final aggregate decryption only.

## Build

```bash
cd paper
pdflatex article
bibtex article
pdflatex article
pdflatex article
```

## Structure

- `article.tex` — title block, section includes, and bibliography hook
- `conf/` — template package configuration and macros
- `sections/` — paper content split by logical section
- `biblio/` — selected CryptoBib entries, abbreviations, and local non-CryptoBib entries

## Positioning

The paper is intentionally framed as:

- a standalone paper on tally integrity in federated elections
- a protocol focused on encrypted local tallies, zero-knowledge validity
  proofs, transcript inclusion, and aggregate-only decryption
- not a claim to solve remote e-voting, malicious local counting, or
  cryptographic proof that a local tally is the true count of a corrupt
  committee

## Current Build Status

- final compiled PDF: `article.pdf`
- validated length: `5 pages`
