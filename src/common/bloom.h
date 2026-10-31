// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// A BLOOM FILTER is a compact way to describe a set of items, such as "the
// addresses in my wallet", that can answer one question: "is this item
// maybe in the set?". The answer is either:
//   - "definitely not", or
//   - "maybe yes": usually right, but sometimes a "false positive".
// It never gives a false "no".
// How it works: start with a long row of bits, all 0. To add an item, hash
// it several times, and each hash picks one bit to set to 1. To check an
// item, hash it the same way: if ANY of its bits is 0, it was never added.
// If all are 1, it was probably added, though other items might have set
// those bits by chance. It is like a coat check where each coat gets
// several numbered pegs. If any of your pegs is empty, your coat is
// definitely not there.
// Bitcoin uses two kinds:
//   - CBloomFilter (BIP 37): a lightweight ("SPV") wallet sends one to a node
//     to ask "only send me transactions that match this". False positives
//     are a feature: they hide which transactions are really the wallet's.
//     It later turned out to protect privacy badly, so Bitcoin Core no longer
//     serves these filters unless the node's owner switches it on
//     (-peerbloomfilters).
//   - CRollingBloomFilter: used inside the node to cheaply remember things
//     it has seen recently, such as transactions or addresses.
// This is networking code, not consensus. The rules of Bitcoin do not
// depend on it.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_COMMON_BLOOM_H
#define BITCOIN_COMMON_BLOOM_H

#include <serialize.h>

#include <cstdint>
#include <span>
#include <vector>

class COutPoint;
class CTransaction;

//! 20,000 items with fp rate < 0.1% or 10,000 items and <0.0001%
// COMMENT HOUSE: Limits on filters that peers send, so nobody can make this
// node do too much work: at most 36,000 bytes and 50 hash functions.
inline constexpr unsigned int MAX_BLOOM_FILTER_SIZE{36'000}; // bytes
inline constexpr unsigned int MAX_HASH_FUNCS = 50;

/**
 * First two bits of nFlags control how much IsRelevantAndUpdate actually updates
 * The remaining bits are reserved
 */
// COMMENT HOUSE: When a transaction matches, should the filter also add that
// transaction's matching outputs? Then the wallet will also see the later
// transaction that spends them, without having to send a new filter.
enum bloomflags
{
    BLOOM_UPDATE_NONE = 0,
    BLOOM_UPDATE_ALL = 1,
    // Only adds outpoints to the filter if the output is a pay-to-pubkey/pay-to-multisig script
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2,
    BLOOM_UPDATE_MASK = 3,
};

/**
 * BloomFilter is a probabilistic filter which SPV clients provide
 * so that we can filter the transactions we send them.
 *
 * This allows for significantly more efficient transaction and block downloads.
 *
 * Because bloom filters are probabilistic, a SPV node can increase the false-
 * positive rate, making us send it transactions which aren't actually its,
 * allowing clients to trade more bandwidth for more privacy by obfuscating which
 * keys are controlled by them.
 */
// COMMENT HOUSE: CBloomFilter (BIP 37):
//   - vData:      the row of bits (stored 8 per byte).
//   - nHashFuncs: how many bits each item sets.
//   - nTweak:     a random number mixed into every hash, so two filters
//                 with the same items still look different.
class CBloomFilter
{
private:
    std::vector<unsigned char> vData;
    unsigned int nHashFuncs;
    unsigned int nTweak;
    unsigned char nFlags;

    unsigned int Hash(unsigned int nHashNum, std::span<const unsigned char> vDataToHash) const;

public:
    /**
     * Creates a new bloom filter which will provide the given fp rate when filled with the given number of elements
     * nFPRate must be in [0, 1].
     * An nElements of 0 creates an empty filter which ignores inserts and matches everything.
     * Note that if the given parameters will result in a filter outside the bounds of the protocol limits,
     * the filter created will be as close to the given parameters as possible within the protocol limits.
     * This will apply if nFPRate is very low or nElements is unreasonably high.
     * nTweak is a constant which is added to the seed value passed to the hash function
     * It should generally always be a random value (and is largely only exposed for unit testing)
     * nFlags should be one of the BLOOM_UPDATE_* enums (not _MASK)
     */
    // COMMENT HOUSE: Make a filter big enough for nElements items with a
    // false-positive rate of nFPRate (for example 0.001 means 1 in 1,000). A
    // lower rate needs a bigger filter. As the developer comment says, a filter
    // made for 0 items is empty and matches everything.
    CBloomFilter(unsigned int nElements, double nFPRate, unsigned int nTweak, unsigned char nFlagsIn);
    CBloomFilter() : nHashFuncs(0), nTweak(0), nFlags(0) {}

    SERIALIZE_METHODS(CBloomFilter, obj) { READWRITE(obj.vData, obj.nHashFuncs, obj.nTweak, obj.nFlags); }

    void insert(std::span<const unsigned char> vKey);
    void insert(const COutPoint& outpoint);

    bool contains(std::span<const unsigned char> vKey) const;
    bool contains(const COutPoint& outpoint) const;

    //! True if the size is <= MAX_BLOOM_FILTER_SIZE and the number of hash functions is <= MAX_HASH_FUNCS
    //! (catch a filter which was just deserialized which was too big)
    bool IsWithinSizeConstraints() const;

    //! Also adds any outputs which match the filter to the filter (to match their spending txes)
    // COMMENT HOUSE: IsRelevantAndUpdate() is what a node runs for each
    // transaction: does it match the wallet's filter? It checks the txid, every
    // piece of data in the outputs' scripts, the coins the inputs spend, and the
    // data in the inputs' scripts. Explained in bloom.cpp.
    bool IsRelevantAndUpdate(const CTransaction& tx);
};

/**
 * RollingBloomFilter is a probabilistic "keep track of most recently inserted" set.
 * Construct it with the number of items to keep track of, and a false-positive
 * rate. Unlike CBloomFilter, by default nTweak is set to a cryptographically
 * secure random value for you. Similarly rather than clear() the method
 * reset() is provided, which also changes nTweak to decrease the impact of
 * false-positives.
 *
 * contains(item) will always return true if item was one of the last N to 1.5*N
 * insert()'ed ... but may also return true for items that were not inserted.
 *
 * It needs around 1.8 bytes per element per factor 0.1 of false positive rate.
 * For example, if we want 1000 elements, we'd need:
 * - ~1800 bytes for a false positive rate of 0.1
 * - ~3600 bytes for a false positive rate of 0.01
 * - ~5400 bytes for a false positive rate of 0.001
 *
 * If we make these simplifying assumptions:
 * - logFpRate / log(0.5) doesn't get rounded or clamped in the nHashFuncs calculation
 * - nElements is even, so that nEntriesPerGeneration == nElements / 2
 *
 * Then we get a more accurate estimate for filter bytes:
 *
 *     3/(log(256)*log(2)) * log(1/fpRate) * nElements
 */
// COMMENT HOUSE: CRollingBloomFilter, a filter that forgets old items.
// It always remembers at least the last N items added. To stay small, it
// works in "generations" and quietly clears the oldest ones as new items
// arrive. The node uses it for things like "have I already told this peer
// about this transaction?".
class CRollingBloomFilter
{
public:
    CRollingBloomFilter(unsigned int nElements, double nFPRate);

    void insert(std::span<const unsigned char> vKey);
    bool contains(std::span<const unsigned char> vKey) const;

    void reset();

private:
    int nEntriesPerGeneration;
    int nEntriesThisGeneration;
    int nGeneration;
    std::vector<uint64_t> data;
    unsigned int nTweak;
    int nHashFuncs;
};

#endif // BITCOIN_COMMON_BLOOM_H
