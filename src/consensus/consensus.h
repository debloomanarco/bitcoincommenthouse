// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// A short list of fixed limits that every node must enforce. Many earlier
// files have already used them. Most of them come from SegWit (BIP 141),
// the 2017 upgrade covered in Phase 7.
//
// SEGWIT IN ONE PARAGRAPH: "Segregated Witness" moved signatures (the
// "witness") out of the scriptSig into a separate part of each transaction
// (CScriptWitness, script/script.h). That had three big effects:
//   1. The txid no longer covers signatures, which fixed "transaction
//      malleability" (see primitives/transaction.cpp).
//   2. Blocks are measured in WEIGHT instead of bytes, and witness bytes are
//      cheaper. This raised the block limit without breaking old nodes.
//   3. New output types (P2WPKH, P2WSH, "bc1q..." addresses), with a version
//      number that later allowed Taproot (Phase 8).
// Old nodes still accept SegWit blocks, because the witness data is simply
// hidden from them. A tightening of the rules that old nodes still accept
// is called a "soft fork".
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstddef>
#include <cstdint>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
// COMMENT HOUSE: The block limits:
//   - MAX_BLOCK_WEIGHT: 4,000,000 weight units per block. Normal bytes count
//     4 units each and witness bytes 1 unit each (see GetTransactionWeight()
//     in consensus/validation.h). A block with no witness data can still only
//     be 1,000,000 bytes, the old limit, which is why old nodes accept it.
//   - MAX_BLOCK_SERIALIZED_SIZE: so the most a block can be in raw bytes is
//     about 4 MB (if it were almost all witness data).
//   - MAX_BLOCK_SIGOPS_COST: at most 80,000 signature operation "cost" per
//     block (see consensus/tx_verify.cpp).
//   - COINBASE_MATURITY: newly mined coins wait 100 blocks before they can be
//     spent (see CheckTxInputs() in consensus/tx_verify.cpp).
inline constexpr unsigned int MAX_BLOCK_SERIALIZED_SIZE{4'000'000};
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
inline constexpr unsigned int MAX_BLOCK_WEIGHT{4'000'000};
/** The maximum allowed number of signature check operations in a block (network rule) */
inline constexpr int64_t MAX_BLOCK_SIGOPS_COST{80'000};
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
inline constexpr int COINBASE_MATURITY = 100;

// COMMENT HOUSE: WITNESS_SCALE_FACTOR = 4 is the witness discount: a normal
// byte weighs 4 times as much as a witness byte.
inline constexpr int WITNESS_SCALE_FACTOR = 4;

inline constexpr size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
inline constexpr size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
// COMMENT HOUSE: A flag that switches on relative time locks (BIP 68, see
// CalculateSequenceLocks() in consensus/tx_verify.cpp).
inline constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
// COMMENT HOUSE: Part of the timewarp protection mentioned in node/miner.cpp:
// the first block of a new difficulty period may not claim to be more than
// 600 seconds (10 minutes) earlier than the block before it.
inline constexpr int64_t MAX_TIMEWARP = 600;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
