// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// It has just one function, CheckTransaction(), the first and simplest check
// every transaction must pass. It is "context-free": it looks only at the
// transaction itself. It does not need to know which coins exist, what time
// it is or which block the transaction is in. That makes it fast, so it runs
// before any slower checks.
// Think of it as checking that a form is filled in properly before checking
// whether what it says is true.
//
// Every failure uses TX_CONSENSUS (see consensus/validation.h): breaking
// any of these rules means the transaction can NEVER be valid.
#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>

#include <set>
#include <string>
#include <utility>
#include <vector>

// COMMENT HOUSE: CheckTransaction() returns true if the transaction passes.
// If not, it returns false and writes the reason into "state". The "&" means
// state is passed by reference: the function fills in the caller's own
// grading sheet instead of a copy.
bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    // Basic checks that don't depend on any context
    // COMMENT HOUSE: Rule 1 and 2: there must be at least one input and at least
    // one output. A transaction that spends nothing, or pays no one, makes no
    // sense.
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    // COMMENT HOUSE: Rule 3: the transaction must be small enough to fit in a
    // block. Without witness data, each byte counts as 4 weight units (see
    // GetTransactionWeight() in consensus/validation.h), and a whole block can
    // hold at most 4,000,000. The witness is left out because it has not been
    // checked yet.
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    // COMMENT HOUSE: Rule 4: every output's amount must be between 0 and 21
    // million bitcoins (MAX_MONEY), and so must the running total. CVE-2010-5139
    // is the 2010 bug mentioned in primitives/transaction.cpp, when someone made
    // about 184 billion bitcoins. Two huge outputs added together "wrapped
    // around" to a small number, so the transaction looked fine. Checking the
    // running total after every output (MoneyRange) stops that.
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    // COMMENT HOUSE: Rule 5: no input may spend the same coin twice inside one
    // transaction. Otherwise someone could list the same 1-bitcoin coin twice
    // and spend 2 bitcoins. CVE-2018-17144 was a real 2018 bug: a speed
    // improvement had accidentally skipped this check during block validation.
    // It could have crashed nodes or, on some versions, created new bitcoins out
    // of thin air. It was found and fixed before anyone used it.
    // How the check works: a std::set is a collection that cannot hold
    // duplicates. insert(...).second is false if the outpoint was already in the
    // set, which means this input is a duplicate.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    // COMMENT HOUSE: Rule 6: a coinbase transaction (which creates new coins, see
    // primitives/transaction.h) has no real coin to spend, so its scriptSig is
    // free space. It must be between 2 and 100 bytes. Miners use it for the
    // block height (required by BIP 34) and sometimes a short message.
    // Every other transaction must NOT have a "null" input, because only a
    // coinbase may create coins from nothing.
    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    return true;
}
