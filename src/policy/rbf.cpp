// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// REPLACE-BY-FEE (RBF): swapping a waiting transaction for a new version
// that pays a higher fee.
// Imagine you send a transaction with a fee that turns out to be too low,
// and it sits in the mempool for hours. RBF lets you make a NEW transaction
// that spends at least one of the same coins, but pays more. The two
// "conflict" (a coin can only be spent once), so nodes must keep only one.
// With RBF they keep the one that pays more, and miners prefer it too.
// This is policy, not consensus (see policy/policy.cpp). Whichever version
// ends up in a block is valid.
// The rules below make sure replacements are always worth it for the
// network: each replacement must pay MORE in total, pay extra for its own
// relay, and make the mempool better overall. Otherwise someone could
// replace a transaction thousands of times, each time adding just 1
// satoshi, and make every node do lots of work for almost nothing.
#include <policy/rbf.h>

#include <consensus/amount.h>
#include <kernel/mempool_entry.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/rbf.h>

#include <limits>
#include <vector>

#include <compare>

// COMMENT HOUSE: IsRBFOptIn(): did this transaction ask to be replaceable?
// Under BIP 125, a transaction signals "you may replace me" by giving any
// input an nSequence below 0xfffffffe. It also counts if any unconfirmed
// transaction it depends on (an "ancestor") signals. Today, Bitcoin Core
// allows replacing any unconfirmed transaction by default ("full RBF"), so
// this is mostly used to report the signal to users.
RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool)
{
    AssertLockHeld(pool.cs);

    // First check the transaction itself.
    if (SignalsOptInRBF(tx)) {
        return RBFTransactionState::REPLACEABLE_BIP125;
    }

    // If this transaction is not in our mempool, then we can't be sure
    // we will know about all its inputs.
    if (!pool.exists(tx.GetHash())) {
        return RBFTransactionState::UNKNOWN;
    }

    // If all the inputs have nSequence >= maxint-1, it still might be
    // signaled for RBF if any unconfirmed parents have signaled.
    const auto& entry{*Assert(pool.GetEntry(tx.GetHash()))};
    auto ancestors{pool.CalculateMemPoolAncestors(entry)};

    for (CTxMemPool::txiter it : ancestors) {
        if (SignalsOptInRBF(it->GetTx())) {
            return RBFTransactionState::REPLACEABLE_BIP125;
        }
    }
    return RBFTransactionState::FINAL;
}

RBFTransactionState IsRBFOptInEmptyMempool(const CTransaction& tx)
{
    // If we don't have a local mempool we can only check the transaction itself.
    return SignalsOptInRBF(tx) ? RBFTransactionState::REPLACEABLE_BIP125 : RBFTransactionState::UNKNOWN;
}

// COMMENT HOUSE: Find every mempool transaction that would have to be thrown
// out: the transactions that directly conflict with the new one, plus all
// their descendants (they depend on outputs that would disappear). Rule 5:
// refuse if the new transaction conflicts with too many separate groups
// (clusters), because that would be a lot of work to process.
// The function returns nothing (std::nullopt) if all is well, or a text
// reason if the replacement is refused.
std::optional<std::string> GetEntriesForConflicts(const CTransaction& tx,
                                                  CTxMemPool& pool,
                                                  const CTxMemPool::setEntries& iters_conflicting,
                                                  CTxMemPool::setEntries& all_conflicts)
{
    AssertLockHeld(pool.cs);
    // Rule #5: don't consider replacements that conflict directly with more
    // than MAX_REPLACEMENT_CANDIDATES distinct clusters. This implies a bound
    // on how many mempool clusters might need to be re-sorted in order to
    // process the replacement (though the actual number of clusters we
    // relinearize may be greater than this number, due to cluster splitting).
    auto num_clusters = pool.GetUniqueClusterCount(iters_conflicting);
    if (num_clusters > MAX_REPLACEMENT_CANDIDATES) {
        return strprintf("rejecting replacement %s; too many conflicting clusters (%u > %d)",
                tx.GetHash().ToString(),
                num_clusters,
                MAX_REPLACEMENT_CANDIDATES);
    }
    // Calculate the set of all transactions that would have to be evicted.
    for (CTxMemPool::txiter it : iters_conflicting) {
        // The cluster count limit ensures that we won't do too much work on a
        // single invocation of this function.
        pool.CalculateDescendants(it, all_conflicts);
    }
    return std::nullopt;
}

// COMMENT HOUSE: A replacement may not depend on a transaction it is
// replacing. That would make no sense: it would need the very coins it is
// trying to make disappear.
std::optional<std::string> EntriesAndTxidsDisjoint(const CTxMemPool::setEntries& ancestors,
                                                   const std::set<Txid>& direct_conflicts,
                                                   const Txid& txid)
{
    for (CTxMemPool::txiter ancestorIt : ancestors) {
        const Txid& hashAncestor = ancestorIt->GetTx().GetHash();
        if (direct_conflicts.contains(hashAncestor)) {
            return strprintf("%s spends conflicting transaction %s",
                             txid.ToString(),
                             hashAncestor.ToString());
        }
    }
    return std::nullopt;
}

// COMMENT HOUSE: The fee rules:
//   - Rule 3: the replacement must pay at least as much in TOTAL fees as
//     everything it replaces.
//   - Rule 4: on top of that, it must pay for its OWN relay, at the
//     incremental relay fee (0.1 sat/vB by default, see policy/policy.h).
//     That makes repeated tiny bumps cost real money.
std::optional<std::string> PaysForRBF(CAmount original_fees,
                                      CAmount replacement_fees,
                                      size_t replacement_vsize,
                                      CFeeRate relay_fee,
                                      const Txid& txid)
{
    // Rule #3: The replacement fees must be greater than or equal to fees of the
    // transactions it replaces, otherwise the bandwidth used by those conflicting transactions
    // would not be paid for.
    if (replacement_fees < original_fees) {
        return strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                         txid.ToString(), FormatMoney(replacement_fees), FormatMoney(original_fees));
    }

    // Rule #4: The new transaction must pay for its own bandwidth. Otherwise, we have a DoS
    // vector where attackers can cause a transaction to be replaced (and relayed) repeatedly by
    // increasing the fee by tiny amounts.
    CAmount additional_fees = replacement_fees - original_fees;
    if (additional_fees < relay_fee.GetFee(replacement_vsize)) {
        return strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                         txid.ToString(),
                         FormatMoney(additional_fees),
                         FormatMoney(relay_fee.GetFee(replacement_vsize)));
    }
    return std::nullopt;
}

// COMMENT HOUSE: The "feerate diagram" check: after the swap, would the
// mempool be strictly BETTER for miners? Think of lining up all mempool
// transactions from best fee rate to worst and counting how many fees a
// miner would get for each amount of block space. The replacement must make
// that line higher somewhere and lower nowhere. This is a newer and more
// precise version of the old rule "the new fee rate must be higher".
std::optional<std::pair<DiagramCheckError, std::string>> ImprovesFeerateDiagram(CTxMemPool::ChangeSet& changeset)
{
    // Require that the replacement strictly improves the mempool's feerate diagram.
    const auto chunk_results{changeset.CalculateChunksForRBF()};

    if (!chunk_results.has_value()) {
        return std::make_pair(DiagramCheckError::UNCALCULABLE, util::ErrorString(chunk_results).original);
    }

    if (!std::is_gt(CompareChunks(chunk_results.value().second, chunk_results.value().first))) {
        return std::make_pair(DiagramCheckError::FAILURE, "insufficient feerate: does not improve feerate diagram");
    }
    return std::nullopt;
}
