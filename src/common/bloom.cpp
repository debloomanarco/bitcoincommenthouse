// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// The code for the bloom filters described in common/bloom.h. Read that
// first for the idea: a row of bits, several hashes per item, and answers
// of "definitely not" or "maybe".
#include <common/bloom.h>

#include <hash.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <script/solver.h>
#include <span.h>
#include <streams.h>
#include <util/check.h>
#include <util/fastrange.h>
#include <util/overflow.h>

#include <algorithm>
#include <cmath>
#include <compare>
#include <vector>

// COMMENT HOUSE: ln(2) and ln(2) squared, used in the formulas for the best
// filter size and number of hash functions (ln is the natural logarithm).
static constexpr double LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455;
static constexpr double LN2 = 0.6931471805599453094172321214581765680755001343602552;

// COMMENT HOUSE: BloomFilterSize() works out how many BYTES the filter needs
// for a number of items and a false-positive rate. The formula is
//     bits = -items x ln(rate) / ln(2)^2
// then it is capped at the protocol limit and divided by 8 to get bytes.
// For example, 1,000 items at a 1% rate needs about 9,600 bits (1,200 bytes).
// Two special cases come first. They were added by a 2026 upstream fix, so
// odd inputs can no longer make the maths misbehave:
//   - 0 items: the filter is empty (size 0), which means "match everything".
//   - a rate of 0 (never wrong): impossible in theory, because ln(0) is
//     minus infinity. It gets the biggest filter allowed instead.
// Assert() stops the program if the rate is not a real number between 0 and
// 1, because that would be a programming mistake.
static unsigned int BloomFilterSize(const unsigned int elements, const double false_positive_rate)
{
    Assert(std::isfinite(false_positive_rate) && false_positive_rate >= 0 && false_positive_rate <= 1);
    if (elements == 0) return 0; // Must precede the zero-rate case to preserve empty-filter semantics.
    if (false_positive_rate == 0) return MAX_BLOOM_FILTER_SIZE; // Avoid log(0) raising FE_DIVBYZERO.
    return std::min(-1 / LN2SQUARED * elements * log(false_positive_rate), MAX_BLOOM_FILTER_SIZE * 8.0) / 8;
}

// COMMENT HOUSE: Build a filter: size the bit row with BloomFilterSize(), then
// choose how many hash functions to use (bits per item x ln(2), up to the
// limit). With 0 items there are 0 hash functions, which avoids dividing by
// zero.
CBloomFilter::CBloomFilter(const unsigned int nElements, const double nFPRate, const unsigned int nTweakIn, unsigned char nFlagsIn) :
    /**
     * The ideal size for a bloom filter with a given number of elements and false positive rate is:
     * - nElements * log(fp rate) / ln(2)^2
     * We ignore filter parameters which will create a bloom filter larger than the protocol limits
     */
    vData(BloomFilterSize(nElements, nFPRate)),
    /**
     * The ideal number of hash functions is filter size * ln(2) / number of elements
     * Again, we ignore filter parameters which will create a bloom filter with more hash functions than the protocol limits
     * See https://en.wikipedia.org/wiki/Bloom_filter for an explanation of these formulas
     */
    nHashFuncs(nElements == 0 ? 0 : std::min((unsigned int)(vData.size() * 8 / nElements * LN2), MAX_HASH_FUNCS)),
    nTweak(nTweakIn),
    nFlags(nFlagsIn)
{
}

// COMMENT HOUSE: Hash number nHashNum of an item. MurmurHash3 is a fast hash
// that is NOT cryptographic (unlike SHA-256), which is fine here. Each hash
// number uses a different starting value ("seed"), mixed with nTweak. The
// result modulo (% ) the number of bits picks one bit position.
inline unsigned int CBloomFilter::Hash(unsigned int nHashNum, std::span<const unsigned char> vDataToHash) const
{
    // 0xFBA4C795 chosen as it guarantees a reasonable bit difference between nHashNum values.
    return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash) % (vData.size() * 8);
}

// COMMENT HOUSE: Add an item: for each hash function, set its chosen bit to 1.
// nIndex >> 3 picks the byte (dividing by 8), and 7 & nIndex picks the bit
// inside it. An empty filter is skipped. CVE-2013-5700 was a 2013 bug where
// an empty filter from a peer made nodes divide by zero and crash.
void CBloomFilter::insert(std::span<const unsigned char> vKey)
{
    if (vData.empty()) // Avoid divide-by-zero (CVE-2013-5700)
        return;
    for (unsigned int i = 0; i < nHashFuncs; i++)
    {
        unsigned int nIndex = Hash(i, vKey);
        // Sets bit nIndex of vData
        vData[nIndex >> 3] |= (1 << (7 & nIndex));
    }
}

void CBloomFilter::insert(const COutPoint& outpoint)
{
    DataStream stream{};
    stream << outpoint;
    insert(MakeUCharSpan(stream));
}

// COMMENT HOUSE: Check an item: if ANY of its bits is 0, the answer is
// "definitely not". If all are 1, it is "maybe". An empty filter matches
// everything.
bool CBloomFilter::contains(std::span<const unsigned char> vKey) const
{
    if (vData.empty()) // Avoid divide-by-zero (CVE-2013-5700)
        return true;
    for (unsigned int i = 0; i < nHashFuncs; i++)
    {
        unsigned int nIndex = Hash(i, vKey);
        // Checks bit nIndex of vData
        if (!(vData[nIndex >> 3] & (1 << (7 & nIndex))))
            return false;
    }
    return true;
}

bool CBloomFilter::contains(const COutPoint& outpoint) const
{
    DataStream stream{};
    stream << outpoint;
    return contains(MakeUCharSpan(stream));
}

bool CBloomFilter::IsWithinSizeConstraints() const
{
    return vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS;
}

// COMMENT HOUSE: IsRelevantAndUpdate(): does this transaction interest the
// wallet that sent the filter? It matches if the filter contains:
//   1. the transaction's txid,
//   2. any data pushed in an output's locking script (such as a public key
//      hash). With the update flags, that output's outpoint is added to the
//      filter, so the later transaction that spends it will match too,
//   3. the outpoint of any coin an input spends, or
//   4. any data pushed in an input's unlocking script (such as a public key).
// It reads scripts with GetOp() from script/script.h.
bool CBloomFilter::IsRelevantAndUpdate(const CTransaction& tx)
{
    bool fFound = false;
    // Match if the filter contains the hash of tx
    //  for finding tx when they appear in a block
    if (vData.empty()) // zero-size = "match-all" filter
        return true;
    const Txid& hash = tx.GetHash();
    if (contains(hash.ToUint256()))
        fFound = true;

    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        // Match if the filter contains any arbitrary script data element in any scriptPubKey in tx
        // If this matches, also add the specific output that was matched.
        // This means clients don't have to update the filter themselves when a new relevant tx
        // is discovered in order to find spending transactions, which avoids round-tripping and race conditions.
        CScript::const_iterator pc = txout.scriptPubKey.begin();
        std::vector<unsigned char> data;
        while (pc < txout.scriptPubKey.end())
        {
            opcodetype opcode;
            if (!txout.scriptPubKey.GetOp(pc, opcode, data))
                break;
            if (data.size() != 0 && contains(data))
            {
                fFound = true;
                if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
                    insert(COutPoint(hash, i));
                else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY)
                {
                    std::vector<std::vector<unsigned char> > vSolutions;
                    TxoutType type = Solver(txout.scriptPubKey, vSolutions);
                    if (type == TxoutType::PUBKEY || type == TxoutType::MULTISIG) {
                        insert(COutPoint(hash, i));
                    }
                }
                break;
            }
        }
    }

    if (fFound)
        return true;

    for (const CTxIn& txin : tx.vin)
    {
        // Match if the filter contains an outpoint tx spends
        if (contains(txin.prevout))
            return true;

        // Match if the filter contains any arbitrary script data element in any scriptSig in tx
        CScript::const_iterator pc = txin.scriptSig.begin();
        std::vector<unsigned char> data;
        while (pc < txin.scriptSig.end())
        {
            opcodetype opcode;
            if (!txin.scriptSig.GetOp(pc, opcode, data))
                break;
            if (data.size() != 0 && contains(data))
                return true;
        }
    }

    return false;
}

// COMMENT HOUSE: The rolling filter. You can skip the details. Items are added
// in "generations" of about half of nElements each. Every item stores which
// generation it belongs to, using 2 bits per position. When a third
// generation starts, the bits of the oldest one are wiped, so old items are
// forgotten and the filter never fills up.
CRollingBloomFilter::CRollingBloomFilter(const unsigned int nElements, const double fpRate)
{
    double logFpRate = log(fpRate);
    /* The optimal number of hash functions is log(fpRate) / log(0.5), but
     * restrict it to the range 1-50. */
    nHashFuncs = std::max(1, std::min((int)round(logFpRate / log(0.5)), 50));
    /* In this rolling bloom filter, we'll store between 2 and 3 generations of nElements / 2 entries. */
    nEntriesPerGeneration = CeilDiv(nElements, 2u);
    uint32_t nMaxElements = nEntriesPerGeneration * 3;
    /* The maximum fpRate = pow(1.0 - exp(-nHashFuncs * nMaxElements / nFilterBits), nHashFuncs)
     * =>          pow(fpRate, 1.0 / nHashFuncs) = 1.0 - exp(-nHashFuncs * nMaxElements / nFilterBits)
     * =>          1.0 - pow(fpRate, 1.0 / nHashFuncs) = exp(-nHashFuncs * nMaxElements / nFilterBits)
     * =>          log(1.0 - pow(fpRate, 1.0 / nHashFuncs)) = -nHashFuncs * nMaxElements / nFilterBits
     * =>          nFilterBits = -nHashFuncs * nMaxElements / log(1.0 - pow(fpRate, 1.0 / nHashFuncs))
     * =>          nFilterBits = -nHashFuncs * nMaxElements / log(1.0 - exp(logFpRate / nHashFuncs))
     */
    uint32_t nFilterBits = (uint32_t)ceil(-1.0 * nHashFuncs * nMaxElements / log(1.0 - exp(logFpRate / nHashFuncs)));
    data.clear();
    /* For each data element we need to store 2 bits. If both bits are 0, the
     * bit is treated as unset. If the bits are (01), (10), or (11), the bit is
     * treated as set in generation 1, 2, or 3 respectively.
     * These bits are stored in separate integers: position P corresponds to bit
     * (P & 63) of the integers data[(P >> 6) * 2] and data[(P >> 6) * 2 + 1]. */
    data.resize(CeilDiv(nFilterBits, 64u) << 1);
    reset();
}

/* Similar to CBloomFilter::Hash */
static inline uint32_t RollingBloomHash(unsigned int nHashNum, uint32_t nTweak, std::span<const unsigned char> vDataToHash)
{
    return MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, vDataToHash);
}

void CRollingBloomFilter::insert(std::span<const unsigned char> vKey)
{
    if (nEntriesThisGeneration == nEntriesPerGeneration) {
        nEntriesThisGeneration = 0;
        nGeneration++;
        if (nGeneration == 4) {
            nGeneration = 1;
        }
        uint64_t nGenerationMask1 = 0 - (uint64_t)(nGeneration & 1);
        uint64_t nGenerationMask2 = 0 - (uint64_t)(nGeneration >> 1);
        /* Wipe old entries that used this generation number. */
        for (uint32_t p = 0; p < data.size(); p += 2) {
            uint64_t p1 = data[p], p2 = data[p + 1];
            uint64_t mask = (p1 ^ nGenerationMask1) | (p2 ^ nGenerationMask2);
            data[p] = p1 & mask;
            data[p + 1] = p2 & mask;
        }
    }
    nEntriesThisGeneration++;

    for (int n = 0; n < nHashFuncs; n++) {
        uint32_t h = RollingBloomHash(n, nTweak, vKey);
        int bit = h & 0x3F;
        /* FastMod works with the upper bits of h, so it is safe to ignore that the lower bits of h are already used for bit. */
        uint32_t pos = FastRange32(h, data.size());
        /* The lowest bit of pos is ignored, and set to zero for the first bit, and to one for the second. */
        data[pos & ~1U] = (data[pos & ~1U] & ~(uint64_t{1} << bit)) | (uint64_t(nGeneration & 1)) << bit;
        data[pos | 1] = (data[pos | 1] & ~(uint64_t{1} << bit)) | (uint64_t(nGeneration >> 1)) << bit;
    }
}

bool CRollingBloomFilter::contains(std::span<const unsigned char> vKey) const
{
    for (int n = 0; n < nHashFuncs; n++) {
        uint32_t h = RollingBloomHash(n, nTweak, vKey);
        int bit = h & 0x3F;
        uint32_t pos = FastRange32(h, data.size());
        /* If the relevant bit is not set in either data[pos & ~1] or data[pos | 1], the filter does not contain vKey */
        if (!(((data[pos & ~1U] | data[pos | 1]) >> bit) & 1)) {
            return false;
        }
    }
    return true;
}

void CRollingBloomFilter::reset()
{
    nTweak = FastRandomContext().rand<unsigned int>();
    nEntriesThisGeneration = 0;
    nGeneration = 1;
    std::fill(data.begin(), data.end(), 0);
}
