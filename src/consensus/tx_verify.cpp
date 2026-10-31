// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// consensus/tx_check.cpp checked a transaction on its own. The checks in
// this file need CONTEXT: which coins exist (the UTXO set from coins.h),
// the current block height and the current time. They answer questions like:
//   - Do the coins being spent actually exist, and are they unspent?
//   - Is there enough money in the inputs to pay for the outputs?
//   - Is the transaction still time-locked?
//   - Does it ask for too many signature checks?
//
// The most important function is Consensus::CheckTxInputs() at the bottom.
// Start there, and come back to the time-lock functions afterwards.
#include <consensus/tx_verify.h>

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <tinyformat.h>
#include <util/check.h>
#include <util/moneystr.h>

#include <algorithm>
#include <cstddef>
#include <string>

// COMMENT HOUSE: IsFinalTx(), the ABSOLUTE time lock (nLockTime).
// A transaction can say "I am not valid until block X" or "until date Y".
// It is like a post-dated check that cannot be cashed before the date
// written on it.
//   - nLockTime == 0 means no lock at all.
//   - A value below LOCKTIME_THRESHOLD (500,000,000) is a block HEIGHT.
//   - A larger value is a TIME, in seconds since 1970 (Unix time).
// The long line below picks the right comparison depending on which kind it
// is. The lock is satisfied if nLockTime is less than the current height or
// time. As the developer comment explains, the lock is also switched off if
// every input uses SEQUENCE_FINAL.
bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;

    // Even if tx.nLockTime isn't satisfied by nBlockHeight/nBlockTime, a
    // transaction is still considered final if all inputs' nSequence ==
    // SEQUENCE_FINAL (0xffffffff), in which case nLockTime is ignored.
    //
    // Because of this behavior OP_CHECKLOCKTIMEVERIFY/CheckLockTime() will
    // also check that the spending input's nSequence != SEQUENCE_FINAL,
    // ensuring that an unsatisfied nLockTime value will actually cause
    // IsFinalTx() to return false here:
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

// COMMENT HOUSE: CalculateSequenceLocks(), the RELATIVE time lock (BIP 68).
// This is an advanced function. You can skip it on a first read.
// Instead of "not before block X", a relative lock says "this coin cannot be
// spent until N blocks (or N x 512 seconds) after it was created". It is
// like "you can open this gift one week after you receive it". It is stored
// in each input's nSequence (see the constants on CTxIn in
// primitives/transaction.h) and only applies to version 2 transactions or
// newer.
// This function works out, for all inputs together, the last block height
// and the last time at which the transaction is still locked. Times use the
// "median time past": the middle timestamp of the previous 11 blocks, which
// is harder for a single miner to fake than one block's timestamp.
// std::pair holds two values together: here (height, time).
std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    assert(prevHeights.size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    bool fEnforceBIP68 = tx.version >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            prevHeights[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = prevHeights[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            const int64_t nCoinTime{Assert(block.GetAncestor(std::max(nCoinHeight - 1, 0)))->GetMedianTimePast()};
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

// COMMENT HOUSE: Given the (height, time) pair from above, is the lock over
// for this block? CBlockIndex is a summary of one block in the chain, with
// pprev pointing to the block before it.
bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

// COMMENT HOUSE: SIGNATURE OPERATIONS ("sigops").
// Checking a digital signature is slow work for a computer. If a block could
// ask for millions of signature checks, it would take nodes a long time to
// check it, so there is a limit per block. These functions COUNT how many
// signature checks a transaction may need:
//   - GetLegacySigOpCount(): counts the operations visible directly in the
//     scripts.
//   - GetP2SHSigOpCount():   counts ones hidden inside "pay to script hash"
//     (P2SH) scripts, which are only revealed when spent.
//   - GetTransactionSigOpCost(): adds them all up, including SegWit ones,
//     multiplying older kinds by 4 (WITNESS_SCALE_FACTOR), just like weight.
// Scripts are explained in Phase 6.
unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, script_verify_flags flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

// COMMENT HOUSE: Consensus::CheckTxInputs(), checking the money.
// This answers: "Are the coins real, and do they add up?" Inputs are the
// coins being spent, looked up in the UTXO set ("inputs" here is a
// CCoinsViewCache, see coins.h). nSpendHeight is the height of the block the
// transaction would go into. If everything is fine, the fee is written into
// txfee. This function does NOT check signatures. That happens separately,
// in script checking (Phase 6).
bool Consensus::CheckTxInputs(const CTransaction& tx, TxValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    // are the actual inputs available?
    // COMMENT HOUSE: Check 1: every coin being spent must exist in the UTXO set
    // and be unspent. If one is missing, it was never created or was already
    // spent. Trying to spend a coin twice is called a "double spend".
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent",
                         strprintf("%s: inputs missing/spent", __func__));
    }

    // COMMENT HOUSE: Check 2: go through each input, look up its coin, and add up
    // the total value going in.
    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        // COMMENT HOUSE: Coinbase maturity: newly mined coins cannot be spent until
        // they are 100 blocks deep (COINBASE_MATURITY, in consensus/consensus.h).
        // Sometimes two miners find a block at the same time, and one of those blocks
        // ends up thrown away. Its reward then disappears. Waiting 100 blocks makes
        // sure that does not also undo every payment made with those coins.
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        // COMMENT HOUSE: As in tx_check.cpp, every amount and the running total must
        // stay between 0 and 21 million bitcoins.
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
        }
    }

    // `tx.GetValueOut()` won't throw in validation paths because output-range checks run first
    // (`bad-txns-vout-negative`, `bad-txns-vout-toolarge`, `bad-txns-txouttotal-toolarge`):
    // * `MemPoolAccept::PreChecks`: `CheckTransaction()` is called before this method;
    // * `Chainstate::ConnectBlock`: `CheckTransaction()` is called via `CheckBlock()` before this method.
    // COMMENT HOUSE: Check 3: you cannot spend more than you have. The total of
    // the outputs may not be more than the total of the inputs. Otherwise the
    // transaction would create bitcoins out of nothing.
    const CAmount value_out = tx.GetValueOut();
    if (nValueIn < value_out) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout",
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
    }

    // Tally transaction fees
    // COMMENT HOUSE: The fee is whatever is left over: inputs minus outputs (see
    // primitives/transaction.h). The miner who includes the transaction in a
    // block collects it. The developer comment explains why this last check can
    // never actually fail. It is kept as an extra safety net.
    const CAmount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux)) {
        // Unreachable, given the following preconditions:
        // * `value_out` comes from `tx.GetValueOut()`, which throws unless `MoneyRange(value_out)` and asserts `MoneyRange(nValueOut)` on return.
        // * `MoneyRange(nValueIn)` was enforced in the input loop.
        // * `nValueIn < value_out` was handled above, so `nValueIn >= value_out` here (and `txfee_aux >= 0`).
        // Therefore `0 <= txfee_aux = nValueIn - value_out <= nValueIn <= MAX_MONEY`.
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;
    return true;
}
