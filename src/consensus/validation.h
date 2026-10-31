// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// Phase 3 is about VALIDATION: checking that transactions and blocks follow
// the rules. Every check in Bitcoin Core needs a way to report its answer,
// and this file provides it. The answer is either "valid", or "invalid,
// and here is why". It is like a teacher's grading sheet: not just a mark,
// but a reason written next to it.
//
// The main pieces:
//   - TxValidationResult and BlockValidationResult: lists of the KINDS of
//     reasons a transaction or block can be rejected.
//   - ValidationState: the "grading sheet" every check fills in.
//   - Functions that calculate a transaction's or block's "weight".
//   - GetWitnessCommitmentIndex(): finds the SegWit fingerprint in a block.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_CONSENSUS_VALIDATION_H
#define BITCOIN_CONSENSUS_VALIDATION_H

#include <consensus/consensus.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>


/** Index marker for when no witness commitment is present in a coinbase transaction. */
// COMMENT HOUSE: Two numbers used by GetWitnessCommitmentIndex() at the bottom
// of this file. -1 means "not found". 38 is the smallest size (in bytes) the
// SegWit fingerprint output can have.
inline constexpr int NO_WITNESS_COMMITMENT{-1};

/** Minimum size of a witness commitment structure. Defined in BIP 141. **/
inline constexpr size_t MINIMUM_WITNESS_COMMITMENT{38};

/** A "reason" why a transaction was invalid, suitable for determining whether the
  * provider of the transaction should be banned/ignored/disconnected/etc.
  */
// COMMENT HOUSE: TxValidationResult, the KINDS of reasons a transaction
// can be rejected. The most important difference is between:
//   - TX_CONSENSUS: the transaction breaks a rule EVERY node must enforce.
//     It can never be valid. Whoever sent it may be misbehaving.
//   - TX_NOT_STANDARD and others: the transaction is allowed by the rules,
//     but THIS node chooses not to pass it on ("policy", see
//     policy/policy.cpp). The sender is not necessarily doing anything wrong.
// Knowing which kind it is helps the node decide whether to disconnect from
// the peer that sent it. Others to notice: TX_MISSING_INPUTS (it spends coins
// this node does not know about) and TX_PREMATURE_SPEND (it spends coins that
// are still locked, for example new coinbase coins that are not 100 blocks
// old yet). The "mempool" is the waiting room for transactions that are not
// in a block yet. It is covered later in this phase.
enum class TxValidationResult {
    TX_RESULT_UNSET = 0,     //!< initial value. Tx has not yet been rejected
    TX_CONSENSUS,            //!< invalid by consensus rules
    TX_INPUTS_NOT_STANDARD,   //!< inputs (covered by txid) failed policy rules
    TX_NOT_STANDARD,          //!< otherwise didn't meet our local policy rules
    TX_MISSING_INPUTS,        //!< transaction was missing some of its inputs
    TX_PREMATURE_SPEND,       //!< transaction spends a coinbase too early, or violates locktime/sequence locks
    /**
     * Transaction might have a witness prior to SegWit
     * activation, or witness may have been malleated (which includes
     * non-standard witnesses).
     */
    TX_WITNESS_MUTATED,
    /**
     * Transaction is missing a witness.
     */
    TX_WITNESS_STRIPPED,
    /**
     * Tx already in mempool or conflicts with a tx in the chain
     * (if it conflicts with another tx in mempool, we use MEMPOOL_POLICY as it failed to reach the RBF threshold)
     * Currently this is only used if the transaction already exists in the mempool or on chain.
     */
    TX_CONFLICT,
    TX_MEMPOOL_POLICY,        //!< violated mempool's fee/size/descendant/RBF/etc limits
    TX_NO_MEMPOOL,            //!< this node does not have a mempool so can't validate the transaction
    TX_RECONSIDERABLE,        //!< fails some policy, but might be acceptable if submitted in a (different) package
    TX_UNKNOWN,               //!< transaction was not validated because package failed
};

/** A "reason" why a block was invalid, suitable for determining whether the
  * provider of the block should be banned/ignored/disconnected/etc.
  * These are much more granular than the rejection codes, which may be more
  * useful for some other use-cases.
  */
// COMMENT HOUSE: BlockValidationResult, the same idea for blocks. For
// example, BLOCK_INVALID_HEADER means the proof-of-work is wrong,
// BLOCK_MUTATED is the duplicate-transaction trick from consensus/merkle.cpp,
// and BLOCK_TIME_FUTURE means the block claims to be from more than 2 hours
// in the future.
enum class BlockValidationResult {
    BLOCK_RESULT_UNSET = 0,  //!< initial value. Block has not yet been rejected
    BLOCK_CONSENSUS,         //!< invalid by consensus rules (excluding any below reasons)
    BLOCK_CACHED_INVALID,    //!< this block was cached as being invalid and we didn't store the reason why
    BLOCK_INVALID_HEADER,    //!< invalid proof of work or time too old
    BLOCK_MUTATED,           //!< the block's data didn't match the data committed to by the PoW
    BLOCK_MISSING_PREV,      //!< We don't have the previous block the checked one is built on
    BLOCK_INVALID_PREV,      //!< A block this one builds on is invalid
    BLOCK_TIME_FUTURE,       //!< block timestamp was > 2 hours in the future (or our clock is bad)
    BLOCK_HEADER_LOW_WORK    //!< the block header may be on a too-little-work chain
};



/** Template for capturing information about block/transaction validation. This is instantiated
 *  by TxValidationState and BlockValidationState for validation information on transactions
 *  and blocks respectively. */
// COMMENT HOUSE: ValidationState, the "grading sheet".
// A check creates one of these, and if something is wrong it calls Invalid()
// with a reason. Whoever asked for the check can then read the answer.
// It is always in one of three modes:
//   - M_VALID:   nothing wrong found (the starting mode).
//   - M_INVALID: the transaction or block broke a rule.
//   - M_ERROR:   something went wrong on THIS computer (for example, the disk
//                could not be read). That says nothing about whether the
//                transaction or block is good.
// "template <typename Result>" means this class is written once but works for
// both kinds of results. Result is filled in later, see the two lines after
// the class.
template <typename Result>
class ValidationState
{
private:
    enum class ModeState {
        M_VALID,   //!< everything ok
        M_INVALID, //!< network rule violation (DoS value may be set)
        M_ERROR,   //!< run-time error
    } m_mode{ModeState::M_VALID};
    Result m_result{};
    std::string m_reject_reason;
    std::string m_debug_message;

public:
    // COMMENT HOUSE: Invalid() records why something failed. It always returns
    // false, so a check can write "return state.Invalid(...);" to record the
    // reason and report failure in one step. reject_reason is a short code like
    // "bad-txns-vout-negative", and debug_message can add details.
    bool Invalid(Result result,
                 const std::string& reject_reason = "",
                 const std::string& debug_message = "")
    {
        m_result = result;
        m_reject_reason = reject_reason;
        m_debug_message = debug_message;
        if (m_mode != ModeState::M_ERROR) m_mode = ModeState::M_INVALID;
        return false;
    }
    // COMMENT HOUSE: Error() records a problem with this computer, not with the
    // data being checked.
    bool Error(const std::string& reject_reason)
    {
        if (m_mode == ModeState::M_VALID)
            m_reject_reason = reject_reason;
        m_mode = ModeState::M_ERROR;
        return false;
    }
    bool IsValid() const { return m_mode == ModeState::M_VALID; }
    bool IsInvalid() const { return m_mode == ModeState::M_INVALID; }
    bool IsError() const { return m_mode == ModeState::M_ERROR; }
    Result GetResult() const { return m_result; }
    std::string GetRejectReason() const { return m_reject_reason; }
    std::string GetDebugMessage() const { return m_debug_message; }
    std::string ToString() const
    {
        if (IsValid()) {
            return "Valid";
        }

        if (!m_debug_message.empty()) {
            return m_reject_reason + ", " + m_debug_message;
        }

        return m_reject_reason;
    }
};

// COMMENT HOUSE: The two real grading sheets: one for transactions and one
// for blocks. They are the template above, filled in with each result list.
class TxValidationState : public ValidationState<TxValidationResult> {};
class BlockValidationState : public ValidationState<BlockValidationResult> {};

// These implement the weight = (stripped_size * 4) + witness_size formula,
// using only serialization with and without witness data. As witness_size
// is equal to total_size - stripped_size, this formula is identical to:
// weight = (stripped_size * 3) + total_size.
// COMMENT HOUSE: WEIGHT, how much block space something uses.
// Since SegWit, a block's limit is measured in "weight units", not bytes:
//   - each byte of ordinary transaction data counts as 4 weight units,
//   - each byte of witness (signature) data counts as only 1.
// This gives witness data a discount. The block limit is 4,000,000 weight
// units (MAX_BLOCK_WEIGHT in consensus/consensus.h). The developer comment
// above shows how the formula is rearranged so it can be calculated just by
// measuring the size with and without witness data. WITNESS_SCALE_FACTOR is
// 4. SegWit is explained fully in a later phase.
static inline int32_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(TX_NO_WITNESS(tx)) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(TX_WITH_WITNESS(tx));
}
static inline int64_t GetBlockWeight(const CBlock& block)
{
    return ::GetSerializeSize(TX_NO_WITNESS(block)) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(TX_WITH_WITNESS(block));
}
static inline int64_t GetTransactionInputWeight(const CTxIn& txin)
{
    // scriptWitness size is added here because witnesses and txins are split up in segwit serialization.
    return ::GetSerializeSize(TX_NO_WITNESS(txin)) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(TX_WITH_WITNESS(txin)) + ::GetSerializeSize(txin.scriptWitness.stack);
}

/** Compute at which vout of the block's coinbase transaction the witness commitment occurs, or -1 if not found */
// COMMENT HOUSE: Since SegWit, each block also needs a fingerprint of all
// witness data (BlockWitnessMerkleRoot() in consensus/merkle.cpp). There was
// no room for it in the 80-byte header, so it is placed in an output of the
// coinbase transaction (block.vtx[0]). This function searches the coinbase's
// outputs for one that starts with the special bytes OP_RETURN, 0x24, 0xaa,
// 0x21, 0xa9, 0xed. OP_RETURN marks an output that can never be spent, used
// only to store data. If several match, the last one counts.
inline int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = NO_WITNESS_COMMITMENT;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            const CTxOut& vout = block.vtx[0]->vout[o];
            if (vout.scriptPubKey.size() >= MINIMUM_WITNESS_COMMITMENT &&
                vout.scriptPubKey[0] == OP_RETURN &&
                vout.scriptPubKey[1] == 0x24 &&
                vout.scriptPubKey[2] == 0xaa &&
                vout.scriptPubKey[3] == 0x21 &&
                vout.scriptPubKey[4] == 0xa9 &&
                vout.scriptPubKey[5] == 0xed) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}

#endif // BITCOIN_CONSENSUS_VALIDATION_H
