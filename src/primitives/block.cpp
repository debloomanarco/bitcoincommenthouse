// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// The code for the two functions primitives/block.h announced: GetHash()
// and ToString(). Read block.h first.
#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

#include <memory>
#include <sstream>

// COMMENT HOUSE: A block's hash. HashWriter turns the 80-byte header into
// bytes and runs them through double SHA-256 (see hash.h). This is the
// number miners are trying to make small enough. Notice that only the header
// (*this) is hashed, not the transaction list.
uint256 CBlockHeader::GetHash() const
{
    return (HashWriter{} << *this).GetHash();
}

// COMMENT HOUSE: A readable description of the block, for logs and debugging:
// the header fields on one line, then each transaction underneath.
std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
