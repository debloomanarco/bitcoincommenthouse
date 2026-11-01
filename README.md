Bitcoin Core Comment House
=====================================

https://bitcoincore.org

For an immediately usable, binary version of the Bitcoin Core software, see
https://bitcoincore.org/en/download/.

What is Bitcoin Comment House?
---------------------

Bitcoin Comment House is an educational project that adds comments to Core so that highschoolers can understand since comments on the main repo are discourage because of clutter.


Bitcoin Comment House: Proposed Learning Sequence

Status: comments have been added to the code. Every file in the eight phases below now has beginner explanations, and so do the extra files listed in "Additional files with comments" further down: 59 files and 614 notes in total. The code itself has not been changed. With the comments taken out, every file is identical to Bitcoin Core.

To find the explanations, search for the marker // COMMENT HOUSE: (for example, grep -rn "COMMENT HOUSE" src). Most commented files start with a "What is this file?" note that says what the file does and which files to read first.

The line numbers below come from the original Bitcoin Core files. Adding comments has moved them, so search for the function name instead.

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

Additional files with comments

After the eight phases were finished, these files were commented too. They fill gaps that the earlier notes point to, or connect the code to things readers have seen, like a Bitcoin address.

Filling gaps in the course
- chain.h and chain.cpp: the node's map of the blockchain. CBlockIndex is an "index card" for each block (pprev, nHeight, nChainWork, GetMedianTimePast()), and CChain is the active chain. Read these after Phase 2.
- primitives/transaction_identifier.h: Txid and Wtxid, and why they are separate types.
- undo.h: undo data, the "receipts" that let a block be taken back off the chain during a reorg.
- coins.cpp: how coins are looked up, added and spent in the UTXO cache.
- consensus/tx_check.h and consensus/tx_verify.h: the headers for tx_check.cpp and tx_verify.cpp.

Addresses: how "1...", "3..." and "bc1..." addresses work
- addresstype.h and addresstype.cpp: which locking script each kind of address stands for.
- base58.cpp: the original "1..." and "3..." address format and its checksum.
- key_io.cpp: turning addresses and private keys into text and back.
- bech32.h: the header for bech32.cpp.

Fees and the mempool
- policy/feerate.h: fee rates in sat/vB.
- policy/policy.h: the default numbers behind this node's policy rules.
- policy/rbf.cpp: replace-by-fee, swapping a stuck transaction for one that pays more.
- txmempool.h: the mempool, the waiting room for unconfirmed transactions.

Supporting files
- hash.cpp, uint256.cpp: small companions to Phase 1.
- versionbits.cpp: how miners vote on upgrades (BIP 9). Read it after consensus/params.h.
- script/script.cpp: the helper functions behind script/script.h.
- kernel/chainparams.h, node/miner.h: the headers for kernel/chainparams.cpp and node/miner.cpp.

From the October 2026 Bitcoin Core update
When new Bitcoin Core commits were merged in, the code they changed got notes as well:
- common/bloom.h and common/bloom.cpp: bloom filters.
- util/btcsignals.h: the internal event ("signal") system.
- net_processing.cpp: only the wtxidrelay message handling, which the update changed.

Files to deliberately avoid at first

- serialize.h (1,224 lines of advanced C++ templates): use it as a reference only.
- net_processing.cpp, wallet/, qt/, rpc/: important, but not needed to understand the protocol. (net_processing.cpp has only one small note, from the October 2026 update.)
- secp256k1/, leveldb/, crc32c/, minisketch/: copied from upstream projects. Keep them untouched so future updates merge cleanly.

How I'd keep the work safe and traceable

1. One comment marker everywhere: // COMMENT HOUSE:, so grep finds every annotation and reviewers can tell them apart from developer comments.
2. Behavior check on every change: git diff should show only added comment lines. The same goes for updates merged from upstream: the result should always be Bitcoin Core with comments added, and nothing else changed.


Synopsis of the repository folders

Most of what a beginner needs is in src/. The other folders hold everything around the code: how it is built, tested, documented, translated and released. This is a short tour of each one, with the files worth knowing about.

.github/ (GitHub settings and automation)
GitHub reads this folder to decide what happens when someone opens an issue or pull request, or pushes code.
- workflows/ci.yml: the main automated test run ("continuous integration"). On every push and pull request it builds Bitcoin Core and runs the tests on several systems: Linux in many configurations, macOS on ARM, and Windows (built natively and cross-compiled from Linux). It also runs the lint checks, and the test-each-commit job checks that every single commit in a pull request builds and passes, not just the last one.
- ISSUE_TEMPLATE/ (bug.yml, feature_request.yml, gui_issue.yml): the forms people fill in when they report a bug or ask for a feature.
- PULL_REQUEST_TEMPLATE.md: the text shown to anyone opening a pull request.
- actions/: small reusable steps used by ci.yml (caching, Docker setup and similar).
- ci-windows.py, ci-windows-cross.py, ci-test-each-commit-exec.py: helper scripts for those CI jobs.

.tx/ (translations)
- config: the only file. It connects the project to Transifex, a website where volunteers translate the graphical wallet (bitcoin-qt) into other languages. The English source text is src/qt/locale/bitcoin_en.ts, and the translations come back as src/qt/locale/bitcoin_<language>.ts.

ci/ (the scripts behind continuous integration)
.github/workflows/ci.yml says WHEN to test, and this folder says HOW. The scripts run inside Docker containers, so a test environment can be rebuilt exactly.
- README.md: how to run the CI on your own computer.
- test/00_setup_env_*.sh: one file per test setup. Each one names an operating system, a compiler and a list of options. Examples are _native_asan (finds memory bugs), _native_tsan (finds threading bugs), _native_fuzz (fuzz testing), _native_valgrind, _win64 and _mac_cross (building for Windows and macOS from Linux), _arm and _s390x (other kinds of processor), and _native_previous_releases (testing against older versions).
- test/01_base_install.sh, 02_run_container.py, 03_test_script.sh: the steps every setup goes through: install tools, start the container, build and run the tests.
- test_run_all.sh: runs everything for one setup.
- lint/ and lint.py: the style and correctness checks (see test/lint below).

cmake/ (helpers for the build system)
Bitcoin Core is built with CMake. The main instructions are in CMakeLists.txt at the top of the repository and in src/CMakeLists.txt. This folder holds the extra pieces they use.
- module/: small CMake modules that find optional libraries (FindQt.cmake, FindZeroMQ.cmake, FindQRencode.cmake) or check what the compiler supports (CheckCXXFeatures.cmake, TryAppendCXXFlags.cmake).
- secp256k1.cmake, leveldb.cmake, crc32c.cmake, minisketch.cmake, libmultiprocess.cmake: how the libraries bundled in src/ are built.
- bitcoin-build-config.h.in: a template that becomes bitcoin-build-config.h, the file validation.cpp includes first. It records the version number and which features were switched on for this build.
- script/: build-time scripts, for example GenerateBuildInfo.cmake (stamps the build with its git commit) and Coverage.cmake (measures how much of the code the tests reach).

contrib/ (extra tools for developers and maintainers)
None of this is part of the running node. These are tools around it.
- guix/: REPRODUCIBLE BUILDS. Guix builds the official release files in a fixed, fully specified environment, so that many people can each build them separately and get byte-for-byte identical results. If everyone's files match, nobody secretly added anything. guix-build makes the files, guix-attest signs a statement of the results, and guix-verify compares statements from different builders. This is one of the most important security practices in the project.
- verify-commits/: checks that every merge into the main repository was signed by a trusted maintainer. trusted-keys lists their key fingerprints.
- verify-binaries/: lets a user check that a downloaded release is genuine.
- seeds/: makes the built-in list of node addresses (vFixedSeeds in kernel/chainparams.cpp). makeseeds.py chooses reliable nodes, nodes_main.txt is the list, and generate-seeds.py turns it into src/chainparamsseeds.h.
- devtools/: everyday developer tools. Examples are clang-format-diff.py (code formatting), circular-dependencies.py, gen-manpages.py, and headerssync-params.py, which generated the m_headers_sync_params numbers in kernel/chainparams.cpp.
- linearize/: makes a straight, fork-free copy of the blockchain's block files.
- signet/: miner (mines blocks on a custom signet) and getcoins.py (asks a signet "faucet" for free test coins).
- tracing/: example scripts that watch a running node through its tracepoints, the TRACEPOINT lines in coins.cpp and validation.cpp.
- init/: files that let an operating system start bitcoind automatically when the computer boots (systemd, OpenRC and others).
- completions/: tab-completion for bitcoin-cli in bash, fish and zsh.
- asmap/, qos/, zmq/, message-capture/, testgen/, utxo-tools/, macdeploy/, windeploy/, debian/, shell/: smaller tools for specific jobs. The contrib/README.md file describes each one.

depends/ (building the libraries Bitcoin Core needs)
Bitcoin Core relies on a few outside libraries, such as Boost, SQLite (for wallets), ZeroMQ, Qt (for the GUI) and Cap'n Proto (for multiprocess). depends/ downloads exact, known versions of them and builds them the same way every time, which the reproducible Guix builds need. It can also build them for a different system than the one you are on ("cross-compiling"), for example building Windows files on Linux.
- README.md: how to use it. Run make, then point the main build at the result.
- packages/: one recipe (.mk file) per library, giving the version, the download address, the expected checksum and how to build it.
- hosts/ and builders/: settings for the system being built FOR (hosts: linux, darwin for macOS, mingw32 for Windows, freebsd and others) and the system building it (builders).
- patches/: small fixes applied to some libraries before building.
- description.md, packages.md: how the system works and how to add a new library.

doc/ (documentation)
The written documentation, about 200 files. The ones to start with:
- README.md: the index of all documentation.
- build-unix.md, build-osx.md, build-windows.md (and the BSD versions): how to compile Bitcoin Core yourself.
- developer-notes.md: the coding style and rules every contributor follows. It is long (over 1,500 lines), but it explains a great deal about why the code looks the way it does.
- files.md: every file a running node creates in its data folder, such as blocks/blk?????.dat, blocks/rev?????.dat (the undo data from undo.h), chainstate/ (the UTXO set from coins.h) and wallets/.
- bips.md: every Bitcoin Improvement Proposal Bitcoin Core implements, and from which version. It is a useful companion to the BIP numbers in the COMMENT HOUSE notes.
- policy/: mempool-design.md, mempool-replacements.md (the RBF rules in policy/rbf.cpp), mempool-terminology.md and packages.md go deeper into the mempool and policy rules from Phase 3.
- design/: assumeutxo.md, libraries.md and multiprocess.md explain bigger design decisions.
- JSON-RPC-interface.md, REST-interface.md, zmq.md: the ways other programs can talk to a running node.
- psbt.md, descriptors.md, managing-wallets.md, multisig-tutorial.md, offline-signing-tutorial.md: how to use the wallet.
- tor.md, i2p.md, cjdns.md: running a node over privacy networks.
- fuzzing.md, benchmarking.md: the testing and speed-measuring tools.
- bitcoin-conf.md: the bitcoin.conf settings file.
- release-notes/ and release-notes-*.md: what changed in each version. The release-notes-<number>.md files are notes for pull requests that will go into the next release.
- release-process.md: how a new version is made and published.
- man/: the manual pages for bitcoind, bitcoin-cli and the other programs.

src/ (the source code)
This is the code that becomes Bitcoin Core, and it is where all the COMMENT HOUSE notes are. The learning sequence above covers the core files in detail, so this is a map of the rest.
- The programs: bitcoind.cpp (the node, which runs in the background), bitcoin-cli.cpp (a command-line tool for sending commands to it), bitcoin-qt (the graphical wallet, in qt/), bitcoin-tx.cpp (makes and edits transactions offline), bitcoin-wallet.cpp (offline wallet tool), bitcoin-util.cpp and bitcoin.cpp (a single front door that starts the others).
- Consensus and data (covered by the learning sequence): consensus/, primitives/, script/, validation.cpp, coins.*, chain.*, pow.*, kernel/chainparams.cpp, undo.h.
- policy/, txmempool.*, node/miner.cpp: the mempool, policy and block building (Phase 3, Phase 4 and the extra files).
- Networking: net.cpp (connections), net_processing.cpp (handling peer messages), protocol.h (the message types), addrman.cpp (the address book of known nodes), banman.cpp (banned peers), bip324.cpp (encrypted connections between nodes), torcontrol.cpp and i2p.cpp (privacy networks).
- Storage: txdb.cpp (the UTXO database), dbwrapper.cpp (a wrapper around LevelDB), flatfile.cpp (the blk and rev files), index/ (optional extra indexes, such as a full transaction index and compact block filters).
- wallet/: the built-in wallet: keys, addresses, coin selection (coinselection.cpp, choosing which coins to spend) and transaction signing. It is separate from the node and can be switched off.
- rpc/: the commands bitcoin-cli can send, such as getblockchaininfo (rpc/blockchain.cpp), sendrawtransaction and getmempoolinfo.
- qt/: the graphical interface.
- crypto/: hash functions (SHA-256, RIPEMD-160, SHA-512, ChaCha20 and others), including fast versions for particular processors.
- util/, common/, support/, compat/, logging/: general helpers such as strings, time, threads, logging and secure memory.
- interfaces/, ipc/, init/: the boundaries between node, wallet and GUI, so they can run as separate processes ("multiprocess").
- zmq/: publishes notifications, such as "new block", to other programs.
- bench/: speed benchmarks.
- test/: the C++ tests. Unit tests check one piece at a time, and each file matches a source file, for example transaction_tests.cpp, script_tests.cpp, pow_tests.cpp, merkle_tests.cpp and coins_tests.cpp. test/data/ holds official test vectors, such as script_tests.json and sighash.json, that all Bitcoin software can check itself against. test/fuzz/ holds about 140 fuzz tests, which feed huge amounts of random input to the code to find crashes.
- Libraries copied from other projects (do not comment these, keep them identical to their sources): secp256k1/ (the elliptic-curve maths for signatures), leveldb/ (the database), crc32c/ (checksums for LevelDB), minisketch/ (efficient transaction relay) and univalue/ (JSON reading and writing for RPC).

share/ (shared resources)
Files used when installing or running Bitcoin Core, but not compiled into it.
- examples/bitcoin.conf: an example settings file listing every option with a short explanation. It is a good way to see what a node can be configured to do.
- rpcauth/rpcauth.py: makes a username and hashed password, so programs can log in to the node's RPC interface without storing the plain password.
- pixmaps/: the Bitcoin logo at different sizes, used for icons and the Windows installer.
- qt/: files for the graphical wallet's build (Info.plist.in for macOS, translate.cmake for translations).
- setup.nsi.in: the template for the Windows installer.

test/ (functional tests, fuzz runner and lint checks)
The tests in src/test check one small piece of code at a time. The tests here start REAL bitcoind nodes, on a private regtest network (see kernel/chainparams.cpp), and test them from outside, the way a user or another node would.
- functional/: about 290 Python test files, each of which starts one or more nodes and checks a feature from end to end. They are named by area: feature_ (consensus and node features), mempool_, mining_, p2p_ (talking to nodes), rpc_, wallet_ and interface_. Good ones to read alongside the learning sequence:
  - example_test.py: a heavily commented example written to teach how these tests work. Start here.
  - feature_block.py: builds hundreds of valid and invalid blocks and checks that the node accepts or rejects each one. It is like a test of the Phase 3 rules.
  - mining_basic.py: block templates and mining (Phase 4).
  - feature_rbf.py, mempool_accept.py: replace-by-fee and mempool acceptance (policy/rbf.cpp, AcceptToMemoryPool()).
  - p2p_segwit.py and feature_taproot.py: SegWit and Taproot (Phases 7 and 8).
  - test_runner.py: runs all the functional tests, several at a time.
- functional/test_framework/: the Python toolkit the tests are built on. It is in effect a small, simplified copy of Bitcoin in Python: messages.py (transactions, blocks and network messages), script.py (Script and opcodes), key.py (keys and signatures), blocktools.py (making blocks), segwit_addr.py (bech32 addresses), p2p.py (pretending to be a peer) and test_node.py (starting and controlling a bitcoind). Reading these alongside the C++ files they copy is an excellent way to learn.
- fuzz/test_runner.py: runs the fuzz tests from src/test/fuzz.
- lint/: automatic checks on the code itself, such as Python style (lint-python.py), header guards (lint-include-guards.py), include rules (lint-includes.py) and that copied libraries were not edited by mistake (git-subtree-check.sh). That last check matters for Comment House: it is why secp256k1/, leveldb/ and the other copied libraries are never commented.
- README.md: how to run all of the above.
