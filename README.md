Bitcoin Core Comment House
=====================================

https://bitcoincore.org

For an immediately usable, binary version of the Bitcoin Core software, see
https://bitcoincore.org/en/download/.

What is Bitcoin Comment House?
---------------------

Bitcoin Comment House is an educational project that adds comments to Core so that highschoolers can understand since comments on the main repo are discourage because of clutter.


Bitcoin Comment House:

Status: comments have been added to the code. Every file in the eight phases below now has beginner explanations, and so do the extra files listed in "Additional files with comments" further down: 59 files and 614 notes in total. The code itself has not been changed. With the comments taken out, every file is identical to Bitcoin Core.

To find the explanations, search for the marker // COMMENT HOUSE: (for example, grep -rn "COMMENT HOUSE" src). Most commented files start with a "What is this file?" note that says what the file does and which files to read first.

The line numbers below come from the original Bitcoin Core files. Adding comments  

safe and traceable

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
This is the code that becomes Bitcoin Core, and it is where all the COMMENT HOUSE notes are.
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
