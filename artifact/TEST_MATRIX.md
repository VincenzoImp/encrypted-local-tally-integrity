# Test Matrix

## Contract Tests

Covered by `yarn test`:

- owner-only authority registration
- election start only after a valid trustee-registry consistency proof
- election start with election id, public key, and submission deadline
- one encrypted tally submission per authority
- rejection of bad submission signatures
- rejection of unauthorized submitters
- rejection of duplicate submissions
- rejection of malformed public signals
- rejection of verifier-failing submissions
- on-chain aggregate update from accepted ciphertexts
- transcript acceptance only for registered authorities
- automatic transition to `ReadyForDecryption` after full participation
- trustee anchoring with public share metadata and threshold
- rejection of unauthorized or duplicate partial decryption shares
- rejection of verifier-failing partial decryption shares
- cancellation on incomplete submission after deadline

## Replay

Covered by `yarn replay`:

- three registered authorities with public electorate sizes
- two candidates
- key generation, trustee registration, and threshold share generation
- on-chain verification of trustee-registry consistency
- encrypted local tally submission for all authorities
- off-chain verification of each Groth16 proof against `verification_key.json`
- transcript reconstruction and homomorphic aggregation from accepted on-chain ciphertexts
- equality check between transcript-derived aggregate and contract-maintained aggregate
- proof-checked partial decryptions read back from the on-chain decryption transcript
- final-tally recovery from the aggregate ciphertext only
- summary match against `expected/replay-summary.expected.json`
