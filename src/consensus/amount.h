// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This small file answers one question: "How does Bitcoin Core store an
// amount of money?"
//
// The answer: as a whole number of satoshis. A satoshi is the smallest unit
// of bitcoin, and 1 bitcoin = 100,000,000 satoshis (like cents in a dollar,
// but 100 million of them instead of 100). Whole numbers are used instead of
// decimals because computers store decimals like 0.1 only approximately, and
// "approximately" is not good enough for money.
//
// The file defines four things:
//   1. CAmount    - the data type used for every amount of money
//   2. COIN       - how many satoshis are in one bitcoin
//   3. MAX_MONEY  - the largest amount the program will accept
//   4. MoneyRange - a yes/no check: "is this amount allowed?"
//
// It lives in the src/consensus/ folder because these values are part of the
// "consensus rules": rules every Bitcoin node must follow in exactly the same
// way. If two nodes used different values, they would disagree about which
// transactions are valid.

// COMMENT HOUSE: Header guard.
// The #ifndef / #define pair below (and the #endif at the very bottom) makes
// sure this file is only read once, even if many other files include it.
// Read it as: "If BITCOIN_CONSENSUS_AMOUNT_H is not defined yet, define it and
// continue. Otherwise, skip everything down to #endif."
#ifndef BITCOIN_CONSENSUS_AMOUNT_H
#define BITCOIN_CONSENSUS_AMOUNT_H

// COMMENT HOUSE: Brings in the standard C++ library file that provides
// fixed-size whole-number types, such as int64_t used below.
#include <cstdint>

// COMMENT HOUSE: CAmount.
// "typedef" gives a new name to an existing type. Here CAmount becomes another
// name for int64_t: a whole number ("int") stored in exactly 64 bits, which can
// be positive or negative. Its largest value is about 9.2 quintillion
// (9,223,372,036,854,775,807), far more than the number of satoshis that will
// ever exist.
//
// Why a new name instead of just writing int64_t? When you see "CAmount" in
// other files, you instantly know the number means "money, counted in
// satoshis", not a block height, a time, or some other number.
//
// Negative values are allowed because some calculations produce them (for
// example, subtracting one amount from another). A negative amount is never
// valid to send; MoneyRange() at the bottom of this file rejects it.
/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

// COMMENT HOUSE: COIN.
// The number of satoshis in one bitcoin: 100,000,000 (one hundred million).
// So 1.5 BTC is stored as 150,000,000.
//
// Reading the code:
//   - constexpr: the value is a constant, known when the program is built.
//     It can never change while the program runs.
//   - inline: lets this constant live in a header file that many other files
//     include, while the program still treats it as one single constant.
//   - {100'000'000}: the ' marks are just digit separators, like the commas
//     in 100,000,000. They make big numbers easier to read and do not change
//     the value.
/** The amount of satoshis in one BTC. */
inline constexpr CAmount COIN{100'000'000};

// COMMENT HOUSE: MAX_MONEY.
// Equal to 21,000,000 * COIN, which is 2,100,000,000,000,000 satoshis
// (21 million BTC).
//
// The original comment below makes an important point that is easy to miss:
// this is NOT a count of how many bitcoins exist. It is a "sanity check": an
// upper limit that no single amount (or total of amounts) may go over. Any
// number above it must be a mistake or an attack.
//
// The real supply ends up slightly below 21 million. One example you can see
// in this codebase: the reward in the very first block (the "genesis block")
// can never be spent. Search src/validation.cpp for "coinbase is unspendable".
//
// "Overflow bug" refers to a real event. In August 2010, someone made a
// transaction with outputs so huge that adding them up "overflowed" (went past
// the largest number a 64-bit integer can hold and wrapped around), and about
// 184 billion bitcoins were created out of nothing. It was fixed within hours
// with a new version of the software. This bug is publicly tracked as
// CVE-2010-5139. Checking amounts against MAX_MONEY helps prevent anything
// like it from happening again.
//
// Because the consensus code uses this limit, changing the number would make
// a node disagree with the rest of the network about which transactions are
// valid. When nodes split into groups that follow different rules, that is
// called a "fork".
/** No amount larger than this (in satoshi) is valid.
 *
 * Note that this constant is *not* the total money supply, which in Bitcoin
 * currently happens to be less than 21,000,000 BTC for various reasons, but
 * rather a sanity check. As this sanity check is used by consensus-critical
 * validation code, the exact value of the MAX_MONEY constant is consensus
 * critical; in unusual circumstances like a(nother) overflow bug that allowed
 * for the creation of coins out of thin air modification could lead to a fork.
 * */
inline constexpr CAmount MAX_MONEY{21'000'000 * COIN};

// COMMENT HOUSE: MoneyRange.
// A function that takes an amount (nValue) and answers true or false
// ("bool"). It returns true only when BOTH of these hold ("&&" means "and"):
//   - nValue >= 0          the amount is not negative, and
//   - nValue <= MAX_MONEY  the amount is not impossibly large.
//
// Examples:
//   MoneyRange(50 * COIN)      -> true   (50 BTC is fine)
//   MoneyRange(-1)             -> false  (negative)
//   MoneyRange(MAX_MONEY + 1)  -> false  (too large)
//
// "const CAmount&" means the function looks at the amount but promises not to
// change it.
//
// Where it is used: the transaction checks in src/consensus/tx_check.cpp and
// src/consensus/tx_verify.cpp use it to make sure each amount, and the totals
// going into and out of a transaction, stay in range. Totals are checked too,
// not just each amount alone, because two amounts that are each fine can add
// up to one that is not. That is exactly the kind of mistake behind the 2010
// overflow bug.
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

// COMMENT HOUSE: End of the header guard that started near the top.
#endif // BITCOIN_CONSENSUS_AMOUNT_H
