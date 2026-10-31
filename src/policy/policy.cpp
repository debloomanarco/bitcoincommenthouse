// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

// COMMENT HOUSE: What is this file?
// This file teaches one of the most important ideas in Bitcoin:
// CONSENSUS versus POLICY.
//   - CONSENSUS rules (the consensus/ folder) are rules EVERY node must
//     enforce. A block that breaks one is rejected by everyone. Changing them
//     requires the whole network to agree.
//   - POLICY rules (this folder) are choices THIS node makes about which
//     unconfirmed transactions it will accept into its mempool (its waiting
//     room) and pass on to other nodes. Breaking a policy rule does not make
//     a transaction invalid. If a miner puts it in a block anyway, every node
//     still accepts that block.
// An analogy: consensus is the law, and policy is a shop's own rules, like
// "no bare feet". A shop can refuse to serve you, but you are not breaking
// the law.
// Policy exists to protect nodes from spam and from transactions that are
// unusually expensive to check. It also keeps unusual script types free
// for future upgrades. That is why the note above says users may change it.
// A transaction that passes these rules is called "standard".
//
// The main functions:
//   - GetDustThreshold() / IsDust(): is an output too small to be worth it?
//   - IsStandardTx():                the main "is this transaction standard?"
//   - ValidateInputsStandardness(), IsWitnessStandard(): the same for the
//                                    coins being spent and the witness data.
//   - GetVirtualTransactionSize():   the "virtual size" used to work out fees.
#include <policy/policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <tinyformat.h>

#include <algorithm>
#include <cstddef>
#include <vector>

// COMMENT HOUSE: DUST: an output worth so little that spending it would cost
// more in fees than it is worth, like a coin so small that picking it up
// costs more energy than it is worth. Such outputs would sit in the UTXO set
// (see coins.h) forever, taking up space on every node, so this node refuses
// to relay transactions that create them.
// The developer comment explains the maths: estimate how many bytes it takes
// to spend the output, then multiply by a fee rate. At the default rate,
// classic outputs below 546 satoshis and SegWit outputs below 294 satoshis
// count as dust. IsUnspendable() outputs (such as OP_RETURN data outputs)
// can never be spent, so they are not counted as dust.
CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // A typical spendable non-segwit txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a spendable txout less than
    // 182*dustRelayFee/1000 (in satoshis).
    // 546 satoshis at the default rate of 3000 sat/kvB.
    // A typical spendable segwit P2WPKH txout is 31 bytes big, and will
    // need a CTxIn of at least 67 bytes to spend:
    // so dust is a spendable txout less than
    // 98*dustRelayFee/1000 (in satoshis).
    // 294 satoshis at the default rate of 3000 sat/kvB.
    if (txout.scriptPubKey.IsUnspendable())
        return 0;

    uint64_t nSize{GetSerializeSize(txout)};
    int witnessversion = 0;
    std::vector<unsigned char> witnessprogram;

    // Note this computation is for spending a Segwit v0 P2WPKH output (a 33 bytes
    // public key + an ECDSA signature). For Segwit v1 Taproot outputs the minimum
    // satisfaction is lower (a single BIP340 signature) but this computation was
    // kept to not further reduce the dust level.
    // See discussion in https://github.com/bitcoin/bitcoin/pull/22779 for details.
    if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        // sum the sizes of the parts of a transaction input
        // with 75% segwit discount applied to the script size.
        nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
    } else {
        nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
    }

    return dustRelayFeeIn.GetFee(nSize);
}

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    return (txout.nValue < GetDustThreshold(txout, dustRelayFeeIn));
}

// COMMENT HOUSE: Lists the positions of all dust outputs in a transaction.
std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate)
{
    std::vector<uint32_t> dust_outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        if (IsDust(tx.vout[i], dust_relay_rate)) dust_outputs.push_back(i);
    }
    return dust_outputs;
}

// COMMENT HOUSE: IsStandard() checks ONE output's locking script.
// Solver() (script/solver.cpp, Phase 6) recognises which standard "shape" a
// script has, such as pay-to-public-key-hash or Taproot. Any script it does
// not recognise is NONSTANDARD. Multisig ("m of n people must sign") is
// only standard for up to 3 keys.
bool IsStandard(const CScript& scriptPubKey, TxoutType& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    whichType = Solver(scriptPubKey, vSolutions);

    if (whichType == TxoutType::NONSTANDARD) {
        return false;
    } else if (whichType == TxoutType::MULTISIG) {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    }

    return true;
}

// COMMENT HOUSE: IsStandardTx(), the main policy check.
// It returns true if the transaction is standard. If not, it returns false
// and writes a short reason, like "tx-size" or "dust". The checks, in order:
//   1. version:   only known transaction version numbers are accepted.
//   2. tx-size:   the transaction must not be too big. Huge transactions can
//                 take a long time to check, as the developer comment says.
//   3. scriptSig: each input's unlocking script must not be too long, and
//                 must only contain data, not instructions ("push only").
//   4. outputs:   each output must be a standard shape (see IsStandard()).
//                 Data-only outputs (NULL_DATA, using OP_RETURN) are limited
//                 in total size, and bare multisig may be refused.
//   5. dust:      at most a small number of dust outputs is allowed.
// Compare this with CheckTransaction() in consensus/tx_check.cpp: those are
// rules a transaction can never break, while these are only preferences.
bool IsStandardTx(const CTransaction& tx, const std::optional<unsigned>& max_datacarrier_bytes, bool permit_bare_multisig, const CFeeRate& dust_relay_fee, std::string& reason)
{
    if (tx.version > TX_MAX_STANDARD_VERSION || tx.version < TX_MIN_STANDARD_VERSION) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    unsigned int sz = GetTransactionWeight(tx);
    if (sz > MAX_STANDARD_TX_WEIGHT) {
        reason = "tx-size";
        return false;
    }

    for (const CTxIn& txin : tx.vin)
    {
        // Biggest 'standard' txin involving only keys is a 15-of-15 P2SH
        // multisig with compressed keys (remember the MAX_SCRIPT_ELEMENT_SIZE byte limit on
        // redeemScript size). That works out to a (15*(33+1))+3=513 byte
        // redeemScript, 513+1+15*(73+1)+3=1627 bytes of scriptSig, which
        // we round off to 1650(MAX_STANDARD_SCRIPTSIG_SIZE) bytes for
        // some minor future-proofing. That's also enough to spend a
        // 20-of-20 CHECKMULTISIG scriptPubKey, though such a scriptPubKey
        // is not considered standard.
        if (txin.scriptSig.size() > MAX_STANDARD_SCRIPTSIG_SIZE) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    unsigned int datacarrier_bytes_left = max_datacarrier_bytes.value_or(0);
    TxoutType whichType;
    for (const CTxOut& txout : tx.vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            reason = "scriptpubkey";
            return false;
        }

        if (whichType == TxoutType::NULL_DATA) {
            unsigned int size = txout.scriptPubKey.size();
            if (size > datacarrier_bytes_left) {
                reason = "datacarrier";
                return false;
            }
            datacarrier_bytes_left -= size;
        } else if ((whichType == TxoutType::MULTISIG) && (!permit_bare_multisig)) {
            reason = "bare-multisig";
            return false;
        }
    }

    // Only MAX_DUST_OUTPUTS_PER_TX dust is permitted(on otherwise valid ephemeral dust)
    if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
        reason = "dust";
        return false;
    }

    return true;
}

/**
 * Check the total number of non-witness sigops across the whole transaction, as per BIP54.
 */
// COMMENT HOUSE: Counts the signature operations (see consensus/tx_verify.cpp)
// a transaction will run, and refuses it if there are too many. BIP 54 is
// a proposed rule change, so for now this node applies it as policy.
static bool CheckSigopsBIP54(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    Assert(!tx.IsCoinBase());

    unsigned int sigops{0};
    for (const auto& txin: tx.vin) {
        const auto& prev_txo{inputs.AccessCoin(txin.prevout).out};

        // Unlike the existing block wide sigop limit which counts sigops present in the block
        // itself (including the scriptPubKey which is not executed until spending later), BIP54
        // counts sigops in the block where they are potentially executed (only).
        // This means sigops in the spent scriptPubKey count toward the limit.
        // `fAccurate` means correctly accounting sigops for CHECKMULTISIGs(VERIFY) with 16 pubkeys
        // or fewer. This method of accounting was introduced by BIP16, and BIP54 reuses it.
        // The GetSigOpCount call on the previous scriptPubKey counts both bare and P2SH sigops.
        sigops += txin.scriptSig.GetSigOpCount(/*fAccurate=*/true);
        sigops += prev_txo.scriptPubKey.GetSigOpCount(txin.scriptSig);

        if (sigops > MAX_TX_LEGACY_SIGOPS) {
            return false;
        }
    }

    return true;
}

/**
 * Check transaction inputs.
 *
 * This does three things:
 *  * Prevents mempool acceptance of spends of future
 *    segwit versions we don't know how to validate
 *  * Mitigates a potential denial-of-service attack with
 *    P2SH scripts with a crazy number of expensive
 *    CHECKSIG/CHECKMULTISIG operations.
 *  * Prevents spends of unknown/irregular scriptPubKeys,
 *    which mitigates potential denial-of-service attacks
 *    involving expensive scripts and helps reserve them
 *    as potential new upgrade hooks.
 *
 * Note that only the non-witness portion of the transaction is checked here.
 *
 * We also check the total number of non-witness sigops across the whole transaction, as per BIP54.
 */
// COMMENT HOUSE: Unlike IsStandardTx(), which only looks at the transaction
// itself, this function also looks up the coins being SPENT (mapInputs, a
// cache of the UTXO set from coins.h). The developer comment above lists the
// three things it checks.
TxValidationState ValidateInputsStandardness(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    TxValidationState state;
    if (tx.IsCoinBase()) {
        return state; // Coinbases don't use vin normally
    }

    if (!CheckSigopsBIP54(tx, mapInputs)) {
        state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", "non-witness sigops exceed bip54 limit");
        return state;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        std::vector<std::vector<unsigned char> > vSolutions;
        TxoutType whichType = Solver(prev.scriptPubKey, vSolutions);
        if (whichType == TxoutType::NONSTANDARD) {
            state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("input %u script unknown", i));
            return state;
        } else if (whichType == TxoutType::WITNESS_UNKNOWN) {
            // WITNESS_UNKNOWN failures are typically also caught with a policy
            // flag in the script interpreter, but it can be helpful to catch
            // this type of NONSTANDARD transaction earlier in transaction
            // validation.
            state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("input %u witness program is undefined", i));
            return state;
        } else if (whichType == TxoutType::SCRIPTHASH) {
            std::vector<std::vector<unsigned char> > stack;
            ScriptError serror;
            // convert the scriptSig into a stack, so we can inspect the redeemScript
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE, &serror)) {
                state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("p2sh scriptsig malformed (input %u: %s)", i, ScriptErrorString(serror)));
                return state;
            }
            if (stack.empty()) {
                state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("input %u P2SH redeemscript missing", i));
                return state;
            }
            CScript subscript(stack.back().begin(), stack.back().end());
            unsigned int sigop_count = subscript.GetSigOpCount(true);
            if (sigop_count > MAX_P2SH_SIGOPS) {
                state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("p2sh redeemscript sigops exceed limit (input %u: %u > %u)", i, sigop_count, MAX_P2SH_SIGOPS));
                return state;
            }
        }
    }

    return state;
}

// COMMENT HOUSE: The same idea for the witness (SegWit signature) data: it
// must not be unusually large or strangely shaped. SegWit and Taproot are
// explained in Phases 7 and 8.
bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.vin[i].scriptWitness.IsNull())
            continue;

        const CTxOut &prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        // get the scriptPubKey corresponding to this input:
        CScript prevScript = prev.scriptPubKey;

        // witness stuffing detected
        if (prevScript.IsPayToAnchor()) {
            return false;
        }

        bool p2sh = false;
        if (prevScript.IsPayToScriptHash()) {
            std::vector <std::vector<unsigned char> > stack;
            // If the scriptPubKey is P2SH, we try to extract the redeemScript casually by converting the scriptSig
            // into a stack. We do not check IsPushOnly nor compare the hash as these will be done later anyway.
            // If the check fails at this stage, we know that this txid must be a bad one.
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            prevScript = CScript(stack.back().begin(), stack.back().end());
            p2sh = true;
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        // Non-witness program must not be associated with any witness
        if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram))
            return false;

        // Check P2WSH standard limits
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            if (tx.vin[i].scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                return false;
            size_t sizeWitnessStack = tx.vin[i].scriptWitness.stack.size() - 1;
            if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                return false;
            for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                if (tx.vin[i].scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                    return false;
            }
        }

        // Check policy limits for Taproot spends:
        // - MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE limit for stack item size
        // - No annexes
        if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
            // Taproot spend (non-P2SH-wrapped, version 1, witness program size 32; see BIP 341)
            std::span stack{tx.vin[i].scriptWitness.stack};
            if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                // Annexes are nonstandard as long as no semantics are defined for them.
                return false;
            }
            if (stack.size() >= 2) {
                // Script path spend (2 or more stack elements after removing optional annex)
                const auto& control_block = SpanPopBack(stack);
                SpanPopBack(stack); // Ignore script
                if (control_block.empty()) return false; // Empty control block is invalid
                if ((control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
                    // Leaf version 0xc0 (aka Tapscript, see BIP 342)
                    for (const auto& item : stack) {
                        if (item.size() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE) return false;
                    }
                }
            } else if (stack.size() == 1) {
                // Key path spend (1 stack element after removing optional annex)
                // (no policy rules apply)
            } else {
                // 0 stack elements; this is already invalid by consensus rules
                return false;
            }
        }
    }
    return true;
}

// COMMENT HOUSE: Does this transaction spend any SegWit coin? It ignores
// "anchor" outputs, tiny outputs used only to help bump a transaction's
// fee later. This is an advanced detail used by the mempool.
bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts)
{
    if (tx.IsCoinBase()) {
        return false;
    }

    int version;
    std::vector<uint8_t> program;
    for (const auto& txin: tx.vin) {
        const auto& prev_spk{prevouts.AccessCoin(txin.prevout).out.scriptPubKey};

        // Note this includes not-yet-defined witness programs.
        if (prev_spk.IsWitnessProgram(version, program) && !prev_spk.IsPayToAnchor(version, program)) {
            return true;
        }

        // For P2SH extract the redeem script and check if it spends a non-Taproot witness program. Note
        // this is fine to call EvalScript (as done in ValidateInputsStandardness/IsWitnessStandard) because this
        // function is only ever called after IsStandardTx, which checks the scriptsig is pushonly.
        if (prev_spk.IsPayToScriptHash()) {
            // If EvalScript fails or results in an empty stack, the transaction is invalid by consensus.
            std::vector <std::vector<uint8_t>> stack;
            if (!EvalScript(stack, txin.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::BASE)
                || stack.empty()) {
                continue;
            }
            const CScript redeem_script{stack.back().begin(), stack.back().end()};
            if (redeem_script.IsWitnessProgram(version, program)) {
                return true;
            }
        }
    }

    return false;
}

// COMMENT HOUSE: VIRTUAL SIZE ("vsize"), what fees are based on.
// Fees are usually quoted in "satoshis per virtual byte" (sat/vB). The
// virtual size is the weight (see consensus/validation.h) divided by 4 and
// rounded up, so a byte of witness data counts as only a quarter of a byte.
// A transaction with a huge number of signature checks for its size is
// treated as if it were bigger, so it pays fairly for the work it causes.
int64_t GetSigOpsAdjustedWeight(int64_t weight, int64_t sigop_cost, unsigned int bytes_per_sigop)
{
    return std::max(weight, sigop_cost * bytes_per_sigop);
}

int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return (GetSigOpsAdjustedWeight(nWeight, nSigOpCost, bytes_per_sigop) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionWeight(tx), nSigOpCost, bytes_per_sigop);
}

int64_t GetVirtualTransactionInputSize(const CTxIn& txin, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionInputWeight(txin), nSigOpCost, bytes_per_sigop);
}
