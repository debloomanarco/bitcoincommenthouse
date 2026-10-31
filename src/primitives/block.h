// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This file describes what a Bitcoin BLOCK looks like as data. A block is
// a bundle of transactions that gets added to the blockchain, roughly every
// 10 minutes. Every block has two parts:
//   1. CBlockHeader: a small summary (always 80 bytes) with six fields.
//   2. CBlock: the header plus the full list of transactions.
// It also defines CBlockLocator, which nodes use to tell each other which
// part of the chain they already have.
//
// Read primitives/transaction.h first, since a block is mostly a list of
// transactions.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

// COMMENT HOUSE: Other files this one needs. primitives/transaction.h gives the
// transaction types, uint256.h gives the 32-byte numbers used for hashes,
// serialize.h gives the tools for turning objects into bytes, and
// util/time.h gives the time types used by Time() below.
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
// COMMENT HOUSE: CBlockHeader, the block's 80-byte summary.
// The (original, Satoshi-era) comment above describes mining. Mining is about
// this header: miners hash these 80 bytes again and again, changing nNonce
// each time, until the hash comes out as a small enough number.
class CBlockHeader
{
public:
    // header
    // COMMENT HOUSE: The six header fields:
    //   - nVersion:       a version number. Today miners also use some of its
    //                     bits to signal support for proposed rule changes.
    //   - hashPrevBlock:  the hash of the block that came right before this one.
    //                     This is literally the "chain" in blockchain: every block
    //                     points back to its parent. Changing an old block would
    //                     change its hash, breaking every link after it.
    //   - hashMerkleRoot: a single 32-byte fingerprint of ALL the transactions in
    //                     the block (see consensus/merkle.cpp). Change any
    //                     transaction and this changes, so the header "seals" them.
    //   - nTime:          when the block was made, in seconds since 1 January 1970
    //                     (this is called "Unix time").
    //   - nBits:          the difficulty target in a compact form: how small the
    //                     block's hash must be (see pow.cpp in a later phase).
    //   - nNonce:         a number the miner is free to change. "Nonce" means
    //                     "number used once". Miners try billions of values looking
    //                     for a hash that meets the target.
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    // COMMENT HOUSE: A new header starts out with every field set to zero.
    CBlockHeader()
    {
        SetNull();
    }

    // COMMENT HOUSE: The header is turned into bytes in exactly this order. The
    // sizes add up to 80 bytes: 4 + 32 + 32 + 4 + 4 + 4.
    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce); }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        // COMMENT HOUSE: A real block always has a difficulty target, so
        // nBits == 0 is used to mean "this header is empty".
        return (nBits == 0);
    }

    // COMMENT HOUSE: GetHash() gives the block's hash (its ID), calculated in
    // primitives/block.cpp. Only the 80-byte header is hashed, not the
    // transactions. The transactions are still protected, because the header
    // contains their merkle root.
    uint256 GetHash() const;

    // COMMENT HOUSE: Two ways to read the block's time: Time() as a proper time
    // type, and GetBlockTime() as a plain number of seconds.
    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


// COMMENT HOUSE: CBlock, a full block: header plus transactions.
// ": public CBlockHeader" means a CBlock "is a" CBlockHeader with extra parts
// added. This is called inheritance: CBlock gets all six header fields for
// free.
class CBlock : public CBlockHeader
{
public:
    // network and disk
    // COMMENT HOUSE: vtx is the list of transactions in the block. The first one,
    // vtx[0], is always the coinbase transaction, which pays the miner the block
    // reward (new coins plus all the fees). CTransactionRef is a shared pointer to
    // a transaction, so the same transaction can be used in many places without
    // copying it.
    std::vector<CTransactionRef> vtx;

    // Memory-only flags for caching expensive checks
    // COMMENT HOUSE: These flags remember "I already checked this", so slow
    // checks are not repeated. They exist only in memory and are never sent or
    // saved. "mutable" lets them change even on a block that is otherwise
    // treated as read-only.
    mutable bool fChecked;                            // CheckBlock()
    mutable bool m_checked_witness_commitment{false}; // CheckWitnessCommitment()
    mutable bool m_checked_merkle_root{false};        // CheckMerkleRoot()

    CBlock()
    {
        SetNull();
    }

    // COMMENT HOUSE: Builds a block from just a header: everything starts empty,
    // then the header fields are copied in. The transactions stay empty.
    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    // COMMENT HOUSE: A block is turned into bytes as the 80-byte header, followed
    // by the list of transactions.
    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITE(AsBase<CBlockHeader>(obj), obj.vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        m_checked_witness_commitment = false;
        m_checked_merkle_root = false;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
// COMMENT HOUSE: CBlockLocator, "here is where I am in the chain".
// When two nodes meet, one sends a list of block hashes it has (vHave): the
// most recent ones, then further and further back with growing gaps. The
// other node finds the newest hash they both know and sends everything after
// it. The gaps keep the list short even though the chain has hundreds of
// thousands of blocks.
struct CBlockLocator
{
    /** Historically CBlockLocator's version field has been written to network
     * streams as the negotiated protocol version and to disk streams as the
     * client version, but the value has never been used.
     *
     * Hard-code to the highest protocol version ever written to a network stream.
     * SerParams can be used if the field requires any meaning in the future,
     **/
    static constexpr int DUMMY_VERSION = 70016;

    std::vector<uint256> vHave;

    CBlockLocator() = default;

    explicit CBlockLocator(std::vector<uint256>&& have) : vHave(std::move(have)) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = DUMMY_VERSION;
        READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
