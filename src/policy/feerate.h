// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// FEE RATES. A transaction's fee is inputs minus outputs (see
// primitives/transaction.h), but what really matters is the fee RATE: how
// much it pays for each unit of block space it uses. Block space is
// limited, so miners pick the transactions that pay the most per unit
// (see addChunks() in node/miner.cpp). It is like comparing grocery prices
// "per kilogram" instead of "per bag".
// The unit is satoshis per virtual byte (sat/vB). The "virtual size"
// (vsize) is the weight divided by 4, so witness data counts less (see
// GetVirtualTransactionSize() in policy/policy.cpp). For example, a
// transaction of 200 vB that pays 1,000 satoshis has a fee rate of 5 sat/vB.
// Bitcoin Core can also show fee rates in BTC per 1,000 vB (BTC/kvB), an
// older unit. 1 sat/vB is the same as 0.00001 BTC/kvB.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_POLICY_FEERATE_H
#define BITCOIN_POLICY_FEERATE_H

#include <consensus/amount.h>
#include <serialize.h>
#include <util/feefrac.h>
#include <util/fees.h>


#include <cstdint>
#include <string>
#include <type_traits>

// COMMENT HOUSE: Names for the units: BTC (1 bitcoin) and sat (1 satoshi,
// one hundred-millionth of a bitcoin, see consensus/amount.h).
inline const std::string CURRENCY_UNIT = "BTC"; // One formatted unit
inline const std::string CURRENCY_ATOM = "sat"; // One indivisible minimum value unit

enum class FeeRateFormat {
    BTC_KVB, //!< Use BTC/kvB fee rate unit
    SAT_VB,  //!< Use sat/vB fee rate unit
};

/**
 * Fee rate in satoshis per virtualbyte: CAmount / vB
 * the feerate is represented internally as FeeFrac
 */
// COMMENT HOUSE: CFeeRate, a fee rate stored as an exact fraction: a fee in
// satoshis over a size in virtual bytes (FeePerVSize). Keeping both numbers,
// instead of dividing, avoids rounding errors when comparing rates.
class CFeeRate
{
private:
    /** Fee rate in sats/vB (satoshis per N virtualbytes) */
    FeePerVSize m_feerate;

public:
    /** Fee rate of 0 satoshis per 0 vB */
    CFeeRate() = default;
    template<std::integral I> // Disallow silent float -> int conversion
    // COMMENT HOUSE: Make a fee rate from "satoshis per 1,000 vB". The template
    // only accepts whole numbers. Passing a decimal number by mistake would
    // otherwise be quietly rounded.
    explicit constexpr CFeeRate(const I m_feerate_kvb) : m_feerate(FeePerVSize(m_feerate_kvb, 1000)) {}

    /**
     * Construct a fee rate from a fee in satoshis and a vsize in vB.
     *
     * Passing any virtual_bytes less than or equal to 0 will result in 0 fee rate per 0 size.
     */
    CFeeRate(const CAmount& nFeePaid, int32_t virtual_bytes);

    /**
     * Construct from a fee rate expressed as FeePerVSize.
     *
     * Lossless: CFeeRate is internally a FeePerVSize, so the exact
     * fee/vsize fraction is preserved. A feerate whose size is less than
     * or equal to 0 results in 0 fee rate per 0 size.
     */
    explicit CFeeRate(const FeePerVSize& feerate) : m_feerate{feerate.size > 0 ? feerate : FeePerVSize{}} {}

    /**
     * Return the fee in satoshis for the given vsize in vbytes.
     * If the calculated fee would have fractional satoshis, then the
     * returned fee will always be rounded up to the nearest satoshi.
     */
    // COMMENT HOUSE: GetFee(): how much a transaction of this size must pay at
    // this rate. Partial satoshis are always rounded UP, so the fee is never too
    // low.
    CAmount GetFee(int32_t virtual_bytes) const;

    FeePerVSize GetFeePerVSize() const { return m_feerate; }

    /**
     * Return the fee in satoshis for a vsize of 1000 vbytes
     */
    CAmount GetFeePerK() const { return CAmount(m_feerate.EvaluateFeeDown(1000)); }
    // COMMENT HOUSE: Comparing fee rates. ByRatio compares the fractions properly:
    // 1,000 sat for 200 vB (5 sat/vB) counts as higher than 1,500 sat for 400 vB
    // (3.75 sat/vB), even though the second fee is bigger.
    friend std::strong_ordering operator<=>(const CFeeRate& a, const CFeeRate& b) noexcept
    {
        return ByRatio{a.m_feerate} <=> ByRatio{b.m_feerate};
    }
    friend bool operator==(const CFeeRate& a, const CFeeRate& b) noexcept
    {
        return ByRatio{a.m_feerate} == ByRatio{b.m_feerate};
    }
    CFeeRate& operator+=(const CFeeRate& a) {
        m_feerate = FeePerVSize(GetFeePerK() + a.GetFeePerK(), 1000);
        return *this;
    }
    std::string ToString(FeeRateFormat fee_rate_format = FeeRateFormat::BTC_KVB) const;
    friend CFeeRate operator*(const CFeeRate& f, int a) { return CFeeRate(a * f.m_feerate.fee, f.m_feerate.size); }
    friend CFeeRate operator*(int a, const CFeeRate& f) { return CFeeRate(a * f.m_feerate.fee, f.m_feerate.size); }

    SERIALIZE_METHODS(CFeeRate, obj) { READWRITE(obj.m_feerate.fee, obj.m_feerate.size); }
};

#endif // BITCOIN_POLICY_FEERATE_H
