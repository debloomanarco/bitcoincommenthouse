// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// The link between LOCKING SCRIPTS and ADDRESSES. People never type a
// locking script. They type an address, like "1A1zP1...", "3J98t1..." or
// "bc1q...". Under the hood, every address stands for one standard script
// shape (see TxoutType in script/solver.h), plus the important bytes inside
// it (a key hash, a script hash, or a Taproot key).
// This file defines a "destination" (CTxDestination): the address's MEANING,
// before it is written out as text. It has two main functions:
//   - ExtractDestination(): locking script to destination ("who does this
//     output pay?").
//   - GetScriptForDestination(): destination to locking script (to pay an
//     address, build its lock).
// Turning a destination into address TEXT (and back) is done in key_io.cpp,
// using base58.cpp for "1..." and "3..." addresses and bech32.cpp for
// "bc1..." addresses.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_ADDRESSTYPE_H
#define BITCOIN_ADDRESSTYPE_H

#include <attributes.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>
#include <util/check.h>
#include <util/hash_type.h>

#include <algorithm>
#include <variant>
#include <vector>

// COMMENT HOUSE: CNoDestination: "this script has no address". It keeps the
// script itself, for example an OP_RETURN data output or a nonstandard
// script.
class CNoDestination
{
private:
    CScript m_script;

public:
    CNoDestination() = default;
    explicit CNoDestination(const CScript& script) : m_script(script) {}

    const CScript& GetScript() const LIFETIMEBOUND { return m_script; }

    friend bool operator==(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() == b.GetScript(); }
    friend bool operator<(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() < b.GetScript(); }
};

// COMMENT HOUSE: PubKeyDestination: a P2PK output (the whole public key is in
// the lock, as in the genesis block). It has no address format of its own.
struct PubKeyDestination {
private:
    CPubKey m_pubkey;

public:
    explicit PubKeyDestination(const CPubKey& pubkey) : m_pubkey(pubkey) {}

    const CPubKey& GetPubKey() const LIFETIMEBOUND { return m_pubkey; }

    friend bool operator==(const PubKeyDestination& a, const PubKeyDestination& b) { return a.GetPubKey() == b.GetPubKey(); }
    friend bool operator<(const PubKeyDestination& a, const PubKeyDestination& b) { return a.GetPubKey() < b.GetPubKey(); }
};

// COMMENT HOUSE: THE DESTINATION TYPES. Each one wraps the bytes that matter
// for one script shape:
//   - PKHash:              P2PKH, the 20-byte Hash160 of a public key.
//                          Address starts with "1".
//   - ScriptHash:          P2SH, the 20-byte Hash160 of a script. Starts
//                          with "3".
//   - WitnessV0ScriptHash: P2WSH, the 32-byte SHA-256 of a script.
//                          Starts with "bc1q" (long).
//   - WitnessV0KeyHash:    P2WPKH, the 20-byte Hash160 of a key. Starts with
//                          "bc1q" (short).
//   - WitnessV1Taproot:    P2TR, the 32-byte Taproot output key. Starts with
//                          "bc1p".
//   - WitnessUnknown:      a future SegWit version.
//   - PayToAnchor:         the special tiny "anchor" output.
// Each is its own type (like Txid and Wtxid in
// primitives/transaction_identifier.h), so a script hash can never be
// mistaken for a key hash.
struct PKHash : public BaseHash<uint160>
{
    PKHash() : BaseHash() {}
    explicit PKHash(const uint160& hash) : BaseHash(hash) {}
    explicit PKHash(const CPubKey& pubkey);
    explicit PKHash(const CKeyID& pubkey_id);
};
CKeyID ToKeyID(const PKHash& key_hash);

struct WitnessV0KeyHash;

// COMMENT HOUSE: The two "= delete" lines forbid building a ScriptHash
// straight from a key hash. The developer comment warns that this would not
// do what you might expect.
struct ScriptHash : public BaseHash<uint160>
{
    ScriptHash() : BaseHash() {}
    // These don't do what you'd expect.
    // Use ScriptHash(GetScriptForDestination(...)) instead.
    explicit ScriptHash(const WitnessV0KeyHash& hash) = delete;
    explicit ScriptHash(const PKHash& hash) = delete;

    explicit ScriptHash(const uint160& hash) : BaseHash(hash) {}
    explicit ScriptHash(const CScript& script);
};
CScriptID ToScriptID(const ScriptHash& script_hash);

struct WitnessV0ScriptHash : public BaseHash<uint256>
{
    WitnessV0ScriptHash() : BaseHash() {}
    explicit WitnessV0ScriptHash(const uint256& hash) : BaseHash(hash) {}
    explicit WitnessV0ScriptHash(const CScript& script);
};

struct WitnessV0KeyHash : public BaseHash<uint160>
{
    WitnessV0KeyHash() : BaseHash() {}
    explicit WitnessV0KeyHash(const uint160& hash) : BaseHash(hash) {}
    explicit WitnessV0KeyHash(const CPubKey& pubkey);
    explicit WitnessV0KeyHash(const PKHash& pubkey_hash);
};
CKeyID ToKeyID(const WitnessV0KeyHash& key_hash);

struct WitnessV1Taproot : public XOnlyPubKey
{
    WitnessV1Taproot() : XOnlyPubKey() {}
    explicit WitnessV1Taproot(const XOnlyPubKey& xpk) : XOnlyPubKey(xpk) {}
};

//! CTxDestination subtype to encode any future Witness version
struct WitnessUnknown
{
private:
    unsigned int m_version;
    std::vector<unsigned char> m_program;

public:
    WitnessUnknown(unsigned int version, const std::vector<unsigned char>& program) : m_version(version), m_program(program) {}
    WitnessUnknown(int version, const std::vector<unsigned char>& program) : m_version(static_cast<unsigned int>(version)), m_program(program) {}

    unsigned int GetWitnessVersion() const { return m_version; }
    const std::vector<unsigned char>& GetWitnessProgram() const LIFETIMEBOUND { return m_program; }

    friend bool operator==(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.GetWitnessVersion() != w2.GetWitnessVersion()) return false;
        return w1.GetWitnessProgram() == w2.GetWitnessProgram();
    }

    friend bool operator<(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.GetWitnessVersion() < w2.GetWitnessVersion()) return true;
        if (w1.GetWitnessVersion() > w2.GetWitnessVersion()) return false;
        return w1.GetWitnessProgram() < w2.GetWitnessProgram();
    }
};

/** Witness program for Pay-to-Anchor output script type */
// COMMENT HOUSE: Pay-to-Anchor (P2A) is SegWit version 1 with the two-byte
// program 0x4e73. Anyone may spend it. It exists only to let a transaction's
// fee be bumped later by spending it in a child transaction.
inline const std::vector<unsigned char> ANCHOR_BYTES{0x4e, 0x73};

struct PayToAnchor : public WitnessUnknown
{
    PayToAnchor() : WitnessUnknown(1, ANCHOR_BYTES) {
        Assume(CScript::IsPayToAnchor(1, ANCHOR_BYTES));
    };
};

/**
 * A txout script categorized into standard templates.
 *  * CNoDestination: Optionally a script, no corresponding address.
 *  * PubKeyDestination: TxoutType::PUBKEY (P2PK), no corresponding address
 *  * PKHash: TxoutType::PUBKEYHASH destination (P2PKH address)
 *  * ScriptHash: TxoutType::SCRIPTHASH destination (P2SH address)
 *  * WitnessV0ScriptHash: TxoutType::WITNESS_V0_SCRIPTHASH destination (P2WSH address)
 *  * WitnessV0KeyHash: TxoutType::WITNESS_V0_KEYHASH destination (P2WPKH address)
 *  * WitnessV1Taproot: TxoutType::WITNESS_V1_TAPROOT destination (P2TR address)
 *  * PayToAnchor: TxoutType::ANCHOR destination (P2A address)
 *  * WitnessUnknown: TxoutType::WITNESS_UNKNOWN destination (P2W??? address)
 *  A CTxDestination is the internal data type encoded in a bitcoin address
 */
// COMMENT HOUSE: CTxDestination holds exactly ONE of the types above. A
// std::variant is like a box with one compartment per type, where only one
// is in use at a time.
using CTxDestination = std::variant<CNoDestination, PubKeyDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash, WitnessV1Taproot, PayToAnchor, WitnessUnknown>;

/** Check whether a CTxDestination corresponds to one with an address. */
bool IsValidDestination(const CTxDestination& dest);

/**
 * Parse a scriptPubKey for the destination.
 *
 * For standard scripts that have addresses (and P2PK as an exception), a corresponding CTxDestination
 * is assigned to addressRet.
 * For all other scripts. addressRet is assigned as a CNoDestination containing the scriptPubKey.
 *
 * Returns true for standard destinations with addresses - P2PKH, P2SH, P2WPKH, P2WSH, P2TR and P2W??? scripts.
 * Returns false for non-standard destinations and those without addresses - P2PK, bare multisig, null data, and nonstandard scripts.
 */
// COMMENT HOUSE: ExtractDestination(): "who does this output pay?". It uses
// Solver() (script/solver.cpp) to recognise the script's shape, then puts
// the matching destination in addressRet. It returns true only if the
// script has a real address.
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet);

/**
 * Generate a Bitcoin scriptPubKey for the given CTxDestination. Returns a P2PKH
 * script for a CKeyID destination, a P2SH script for a CScriptID, and an empty
 * script for CNoDestination.
 */
// COMMENT HOUSE: GetScriptForDestination(): the reverse. It builds the
// locking script for a destination. For a PKHash, it gives the classic
// OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG.
CScript GetScriptForDestination(const CTxDestination& dest);

#endif // BITCOIN_ADDRESSTYPE_H
