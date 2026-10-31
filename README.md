Bitcoin Core Comment House
=====================================

https://bitcoincore.org

For an immediately usable, binary version of the Bitcoin Core software, see
https://bitcoincore.org/en/download/.

What is Bitcoin Comment House?
---------------------

Bitcoin Comment House is an educational project that adds comments to Core so that highschoolers can understand since comments on the main repo are discourage because of clutter. the Bitcoin peer-to-peer network to download and fully
validate blocks and transactions. 


Bitcoin Comment House: Proposed Learning Sequence

I made no edits. Every file, function and line number below comes from this checkout (beginner-comments branch, which matches v31.0). There are no beginner explanation comments anywhere in the tree yet, so we're starting fresh.

How the repository is organized

┌────────────────────────────────────────┬───────────────────────────────────────────────────────────┬────────────────────────────────────────────────────┐
│                  Area                  │                     What lives there                      │                Good for beginners?                 │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
│ src/consensus/                         │ The rules every node must agree on                        │ ✅ Core material                                   │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
│ src/primitives/                        │ The basic data shapes: transactions and blocks            │ ✅ Start here                                      │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
│ src/script/                            │ Bitcoin's small programming language that locks coins     │ ✅ Middle stage                                    │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
│ src/crypto/, hash.h, key.*, pubkey.*   │ Hashing and signatures                                    │ ✅ After the basics                                │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
│ src/validation.cpp (6,425 lines)       │ Ties all the rules together                               │ ⚠️ Annotate one function at a time                 │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
│ src/node/miner.cpp, pow.cpp            │ Building blocks and proof-of-work                         │ ✅                                                 │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
│ src/policy/                            │ Rules this node chooses to apply, which are not consensus │ ✅ Good for teaching that difference               │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
│ net_processing.cpp, wallet/, qt/, rpc/ │ Networking, wallet, GUI                                   │ ❌ Later or never                                  │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────────┤
│ secp256k1/, leveldb/, minisketch/      │ Outside libraries copied into the repo                    │ ❌ Don't annotate. Keep them identical to upstream │
└────────────────────────────────────────┴───────────────────────────────────────────────────────────┴────────────────────────────────────────────────────┘

The sequence

The phases follow the order you asked for. A rule I used throughout: each file should only depend on ideas from files earlier in the list.

Phase 1: Units and fingerprints

1. consensus/amount.h (29 lines)
- Why: It's the gentlest possible start. It covers satoshis (COIN = 100000000, line 15), the 21 million cap (MAX_MONEY, line 26) and MoneyRange(), a one-line function that's easy to explain fully: what goes in, what it checks, what comes out.
- Analogy: a satoshi is to a bitcoin what a cent is to a dollar, only 100 million times smaller.

2. uint256.h
- Why: Almost every later file uses uint256: transaction IDs, block hashes, merkle roots. Readers need to know it's a fixed 32-byte number before they meet it everywhere.

3. crypto/sha256.h and hash.h
- Why: These introduce hashing, the "digital fingerprint" idea. hash.h has CHash256 (line 24, double SHA-256, used for txids and block hashes), CHash160/Hash160 (lines 49 and 92, used for addresses) and TaggedHash (line 219, which Taproot needs later).
- Skip: the sha256_avx2.cpp-style files. They're hardware speed-ups of the same algorithm and teach nothing new.

Phase 2: What a transaction and a block are

4. primitives/transaction.h and .cpp
- Why: This is the most important file for understanding Bitcoin. COutPoint (line 28) means "which earlier output I'm spending." CTxIn (61) and CTxOut (139) are the inputs and outputs. CTransaction (280) and CMutableTransaction (357) show why there's a frozen version and an editable version.
- Analogy: inputs are bills you hand over, outputs are the new bills and change that come back.

5. primitives/block.h and .cpp
- Why: CBlockHeader has exactly six fields (lines 30–35): nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce. hashPrevBlock is literally the "chain" in blockchain.

6. consensus/merkle.cpp
- Why: ComputeMerkleRoot() (line 46) shows how thousands of transactions are squeezed into one 32-byte fingerprint in the header. The existing developer comment about CVE-2012-2459 (line 12) is a real-world security story beginners can follow.

7. kernel/chainparams.cpp and consensus/params.h
- Why: CreateGenesisBlock() (line 36) builds the very first block. It contains Satoshi's headline, "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks" (line 70). params.h defines the protocol's settings: nSubsidyHalvingInterval, nPowTargetSpacing, SegwitHeight and the BIP 9 upgrade-voting settings (vDeployments). These settings come back in every later phase.

Phase 3: Transaction validation

8. consensus/validation.h
- Why: ValidationState (line 75) is how every check reports "valid" or "invalid, and here's why." Reading it first makes the rejection strings in later files make sense.

9. consensus/tx_check.cpp (60 lines)
- Why: CheckTransaction() (line 11) is the best first example of validation. It's short, needs no context, and checks for no inputs, no outputs, oversized transactions, negative amounts, amounts above MAX_MONEY, and duplicate inputs. Two real CVEs are cited in the existing comments.

10. coins.h
- Why: It introduces the UTXO set, Bitcoin's "list of unspent bills." Coin (line 34) and CCoinsViewCache (line 367) are needed before checking inputs makes sense.

11. consensus/tx_verify.cpp
- Why: Consensus::CheckTxInputs() (line 164) asks whether the coins being spent exist and whether the inputs cover the outputs. It also enforces the 100-block coinbase maturity rule (line 179, COINBASE_MATURITY in consensus.h:19).

12. policy/policy.cpp
- Why: IsStandardTx() (line 99) teaches a key lesson: consensus means "must," policy means "my node prefers." Beginners often mix these up.

13. validation.cpp, selected functions only
- AcceptToMemoryPool() (line 1772): the waiting room for unconfirmed transactions.
- CheckBlock() (line 3950) and ConnectBlock() (line 2292): how a whole block is judged.
- ActivateBestChain() (line 3354): how the node picks the chain with the most work.
- Why selective: at 6,425 lines, annotating all of it would overwhelm a reader. Script checking (CheckInputScripts, line 2058) gets only a placeholder note in this phase, something like "explained in Phase 6."

Phase 4: Mining

14. GetBlockSubsidy() in validation.cpp:1836
- Why: In 12 lines it explains the whole monetary schedule: 50 coins, halved every 210,000 blocks, reaching zero after 64 halvings.

15. pow.cpp and pow.h (171 lines)
- Why: CheckProofOfWork() (line 140) asks whether the hash is below the target. GetNextWorkRequired() (14) and CalculateNextWorkRequired() (50) handle difficulty adjustment.
- Analogy: a lottery where you keep rolling dice until you get a very low number.
- Companion: arith_uint256.h, the version of uint256 that supports arithmetic.

16. node/miner.cpp
- Why: BlockAssembler::CreateNewBlock() (line 122) shows a block being built. Line 178, block_reward = nFees + GetBlockSubsidy(...), connects Phases 3 and 4 directly.

Phase 5: Cryptography (signatures)

17. key.h/key.cpp and pubkey.h/pubkey.cpp
- Why: CKey::Sign() (key.cpp:209) and CPubKey::Verify() (pubkey.cpp:283) make "private key signs, public key verifies" concrete.
- Analogy: a wax seal only you can make, but anyone can recognize.
- The actual math lives in the secp256k1/ subtree. We explain that it does the math, but don't annotate inside it.

Phase 6: Script

18. script/script.h
- Why: It lists the opcodes. The classic payment OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG can be traced through lines 125, 187, 147 and 190. It also defines CScript (line 404).

19. script/solver.h and .cpp
- Why: TxoutType (solver.h:22) is a short catalogue of every standard locking shape, from PUBKEYHASH through WITNESS_V1_TAPROOT. It works as a map for the rest of the course.

20. script/interpreter.cpp, selected functions
- EvalScript() (line 407): the stack machine.
- VerifyScript() (line 2002): unlocking script meets locking script.
- SignatureHash() (line 1600): what exactly gets signed.
- Companion: script/script_error.h, which lists the reasons a script can fail.

Phase 7: SegWit

21. Spread across files already covered
- consensus/consensus.h: WITNESS_SCALE_FACTOR = 4 and MAX_BLOCK_WEIGHT = 4000000 (block weight).
- CScriptWitness in script.h:576.
- The version-0 branch of VerifyWitnessProgram() (interpreter.cpp:1917). The existing comment at line 1938 already names P2WPKH.
- CheckWitnessMalleation() (validation.cpp:3902) and GenerateCoinbaseCommitment() (validation.cpp:4029): how witness data is committed to in a block.
- bech32.cpp: the bc1… address format.
- Why this order: SegWit makes no sense until the reader knows transactions, script and signatures, so it comes back to those files with new eyes.

Phase 8: Taproot

22. Spread across files already covered
- XOnlyPubKey (pubkey.h:226), VerifySchnorr() (pubkey.cpp:236), ComputeTapTweakHash() and CheckTapTweak() (lines 246 and 257).
- In interpreter.cpp: ComputeTapleafHash() (1872), VerifyTaprootCommitment() (1903), SignatureHashSchnorr() (1483), and OP_CHECKSIGADD (script.h:210).
- TaggedHash from Phase 1 pays off here.
- Why last: Taproot combines everything before it: hashing, keys, script, witness and the deployment parameters.

Files to deliberately avoid at first

- serialize.h (1,224 lines of advanced C++ templates): use it as a reference only.
- net_processing.cpp, wallet/, qt/, rpc/: important, but not needed to understand the protocol.
- secp256k1/, leveldb/, crc32c/, minisketch/: copied from upstream projects. Keep them untouched so future updates merge cleanly.

How I'd keep the work safe and traceable

1. One comment marker everywhere: // COMMENT HOUSE:, so grep finds every annotation and reviewers can tell them apart from developer comments.
2. Behavior check on every change: git diff should show only added comment lines. A build plus ctest and the functional tests confirm nothing else changed.
3. Annotation log: a file like doc/beginner/ANNOTATION_LOG.md, with one row per file: path, functions covered, terms defined, analogies used, and the commit that annotated it.
4. Glossary: each term is defined once, where it first appears in this sequence, and later files link back to that first definition.

