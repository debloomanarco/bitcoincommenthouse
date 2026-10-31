// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The Solver functions are used by policy and the wallet, but not consensus.

// COMMENT HOUSE: What is this file?
// A script can be anything, but in practice almost every output uses one
// of a few standard SHAPES ("templates"). This file names those shapes, and
// Solver() (in solver.cpp) recognises which one a script is. As the note
// above says, this is used by policy and wallets, not by consensus. The
// consensus rules simply run the script, whatever its shape.
// TxoutType below works as a map of the whole course.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_SCRIPT_SOLVER_H
#define BITCOIN_SCRIPT_SOLVER_H

#include <attributes.h>
#include <script/script.h>

#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

class CPubKey;

// COMMENT HOUSE: TxoutType, every standard output shape, from oldest to newest:
//   - NONSTANDARD: not one of the shapes below.
//   - ANCHOR:      a tiny "anyone can spend" output used to help bump fees.
//   - PUBKEY (P2PK): "pay to public key". The lock contains the whole public
//                  key: <pubkey> OP_CHECKSIG. Used in the earliest blocks,
//                  including the genesis block.
//   - PUBKEYHASH (P2PKH): "pay to public key hash", the classic "1..."
//                  address. The example at the top of script/script.h.
//   - SCRIPTHASH (P2SH): "pay to script hash" (BIP 16), "3..." addresses.
//                  The lock is only a hash. The spender reveals the real
//                  script.
//   - MULTISIG:    "m of n" keys must sign, for example 2 of 3.
//   - NULL_DATA:   OP_RETURN followed by data. It can never be spent, and it
//                  is used to store a small amount of data in the chain.
//   - WITNESS_V0_KEYHASH (P2WPKH) and WITNESS_V0_SCRIPTHASH (P2WSH): the
//                  SegWit versions of P2PKH and P2SH, "bc1q..." addresses
//                  (Phase 7).
//   - WITNESS_V1_TAPROOT (P2TR): Taproot, "bc1p..." addresses (Phase 8).
//   - WITNESS_UNKNOWN: a future SegWit version that is not defined yet.
enum class TxoutType {
    NONSTANDARD,
    // 'standard' transaction types:
    ANCHOR, //!< anyone can spend script
    PUBKEY,
    PUBKEYHASH,
    SCRIPTHASH,
    MULTISIG,
    NULL_DATA, //!< unspendable OP_RETURN script that carries data
    WITNESS_V0_SCRIPTHASH,
    WITNESS_V0_KEYHASH,
    WITNESS_V1_TAPROOT,
    WITNESS_UNKNOWN, //!< Only for Witness versions not already defined above
};

/** Get the name of a TxoutType as a string */
std::string GetTxnOutputType(TxoutType t);

constexpr bool IsPushdataOp(opcodetype opcode)
{
    return opcode > OP_FALSE && opcode <= OP_PUSHDATA4;
}

/**
 * Parse a scriptPubKey and identify script type for standard scripts. If
 * successful, returns script type and parsed pubkeys or hashes, depending on
 * the type. For example, for a P2SH script, vSolutionsRet will contain the
 * script hash, for P2PKH it will contain the key hash, etc.
 *
 * @param[in]   scriptPubKey   Script to parse
 * @param[out]  vSolutionsRet  Vector of parsed pubkeys and hashes
 * @return                     The script type. TxoutType::NONSTANDARD represents a failed solve.
 */
// COMMENT HOUSE: Solver() is explained in solver.cpp. In short: give it a
// locking script and it returns its shape, plus the important parts (keys
// or hashes) in vSolutionsRet.
TxoutType Solver(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& vSolutionsRet);

/** Generate a P2PK script for the given pubkey. */
// COMMENT HOUSE: These two build locking scripts: P2PK for one key, and a
// multisig script for several keys.
CScript GetScriptForRawPubKey(const CPubKey& pubkey);

/** Determine if script is a "multi_a" script. Returns (threshold, keyspans) if so, and nullopt otherwise.
 *  The keyspans refer to bytes in the passed script. */
std::optional<std::pair<int, std::vector<std::span<const unsigned char>>>> MatchMultiA(const CScript& script LIFETIMEBOUND);

/** Generate a multisig script. */
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);

#endif // BITCOIN_SCRIPT_SOLVER_H
