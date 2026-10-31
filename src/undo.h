// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// UNDO DATA, how a node can take a block back off the chain.
// Connecting a block (ConnectBlock() in validation.cpp) removes every coin
// its transactions spend from the UTXO set (coins.h). But sometimes a block
// must be DISCONNECTED again: for example, when a competing branch turns out
// to have more work (a "reorg", see ActivateBestChain()). To put the spent
// coins back, the node must remember exactly what they were, because once a
// coin is spent it is gone from the UTXO set.
// So, while connecting a block, the node saves a copy of every coin it
// spends. That copy is the "undo data", stored in the rev?????.dat files
// next to the blocks (see BLOCK_HAVE_UNDO in chain.h). It is like keeping
// receipts so you can reverse a purchase.
// Disconnecting a block then means: remove the coins the block created, and
// put back the coins saved in its undo data.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include <coins.h>
#include <compressor.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <serialize.h>

/** Formatter for undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and its metadata as well
 *  (coinbase or not, height). The serialization contains a dummy value of
 *  zero. This is compatible with older versions which expect to see
 *  the transaction version there.
 */
// COMMENT HOUSE: How ONE spent coin is written into the undo file: its height
// and coinbase flag packed into one number (the same trick as Coin in
// coins.h), then the output itself, compressed. The extra 0 byte is only
// there so old versions of Bitcoin Core can still read the files.
struct TxInUndoFormatter
{
    template<typename Stream>
    void Ser(Stream &s, const Coin& txout) {
        uint32_t nCode{(uint32_t{txout.nHeight} << 1) | uint32_t{txout.fCoinBase}};
        ::Serialize(s, VARINT(nCode));
        if (txout.nHeight > 0) {
            // Required to maintain compatibility with older undo format.
            ::Serialize(s, (unsigned char)0);
        }
        ::Serialize(s, Using<TxOutCompression>(txout.out));
    }

    template<typename Stream>
    void Unser(Stream &s, Coin& txout) {
        uint32_t nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        txout.nHeight = nCode >> 1;
        txout.fCoinBase = nCode & 1;
        if (txout.nHeight > 0) {
            // Old versions stored the version number for the last spend of
            // a transaction's outputs. Non-final spends were indicated with
            // height = 0.
            unsigned int nVersionDummy;
            ::Unserialize(s, VARINT(nVersionDummy));
        }
        ::Unserialize(s, Using<TxOutCompression>(txout.out));
    }
};

/** Undo information for a CTransaction */
// COMMENT HOUSE: CTxUndo, the undo data for one transaction: a copy of the
// coin spent by each of its inputs, in the same order as the inputs.
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    SERIALIZE_METHODS(CTxUndo, obj) { READWRITE(Using<VectorFormatter<TxInUndoFormatter>>(obj.vprevout)); }
};

/** Undo information for a CBlock */
// COMMENT HOUSE: CBlockUndo, the undo data for a whole block: one CTxUndo
// for each transaction. The coinbase is skipped, because it spends no
// coins, so there is nothing to put back.
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    SERIALIZE_METHODS(CBlockUndo, obj) { READWRITE(obj.vtxundo); }
};

#endif // BITCOIN_UNDO_H
