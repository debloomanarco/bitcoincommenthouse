// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// The NUMBERS behind this node's policy rules (policy/policy.cpp explains
// consensus versus policy: the law versus a shop's own rules). Each is a
// default setting that the node's owner can usually change with a
// command-line option, the -name in each developer comment.
// Fee settings below are in satoshis per 1,000 virtual bytes (sat/kvB), so
// divide by 1,000 to get sat/vB (see policy/feerate.h). For example, 100
// sat/kvB is 0.1 sat/vB.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_POLICY_POLICY_H
#define BITCOIN_POLICY_POLICY_H

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/solver.h>
#include <util/feefrac.h>

#include <cstdint>
#include <string>

class CCoinsViewCache;
class CFeeRate;
class CScript;

/** Default for -blockmaxweight, which controls the range of block weights the mining code will create **/
// COMMENT HOUSE: Settings for building blocks (node/miner.cpp): how heavy a
// block to make, how much space to keep free for the coinbase, and the
// lowest fee rate a transaction must pay to be included.
inline constexpr unsigned int DEFAULT_BLOCK_MAX_WEIGHT{MAX_BLOCK_WEIGHT};
/** Default for -blockreservedweight **/
inline constexpr unsigned int DEFAULT_BLOCK_RESERVED_WEIGHT{8000};
/** Default sigops cost to reserve for coinbase transaction outputs when creating block templates. */
inline constexpr unsigned int DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS{400};
/** This accounts for the block header, var_int encoding of the transaction count and a minimally viable
 * coinbase transaction. It adds an additional safety margin, because even with a thorough understanding
 * of block serialization, it's easy to make a costly mistake when trying to squeeze every last byte.
 * Setting a lower value is prevented at startup. */
inline constexpr unsigned int MINIMUM_BLOCK_RESERVED_WEIGHT{2000};
/** Default for -blockmintxfee, which sets the minimum feerate for a transaction in blocks created by mining code **/
inline constexpr unsigned int DEFAULT_BLOCK_MIN_TX_FEE{1};
/** The maximum weight for transactions we're willing to relay/mine */
// COMMENT HOUSE: Size limits for one standard transaction:
//   - at most 400,000 weight units, a tenth of a block, so no single
//     transaction can hog a block or be very slow to check.
//   - at least 65 bytes without the witness. A 64-byte transaction could be
//     confused with a pair of hashes inside a merkle tree
//     (consensus/merkle.cpp), which can be used to trick lightweight
//     wallets.
//   - limits on signature operations (see consensus/tx_verify.cpp).
inline constexpr int32_t MAX_STANDARD_TX_WEIGHT{400'000};
/** The minimum non-witness size for transactions we're willing to relay/mine: one larger than 64  */
inline constexpr unsigned int MIN_STANDARD_TX_NONWITNESS_SIZE{65};
/** Maximum number of signature check operations in an IsStandard() P2SH script */
inline constexpr unsigned int MAX_P2SH_SIGOPS{15};
/** The maximum number of sigops we're willing to relay/mine in a single tx */
inline constexpr unsigned int MAX_STANDARD_TX_SIGOPS_COST{MAX_BLOCK_SIGOPS_COST/5};
/** The maximum number of potentially executed legacy signature operations in a single standard tx */
inline constexpr unsigned int MAX_TX_LEGACY_SIGOPS{2'500};
/** Default for -incrementalrelayfee, which sets the minimum feerate increase for mempool limiting or replacement **/
// COMMENT HOUSE: When a transaction is replaced, or the mempool is full, the
// new transaction must pay at least this much more: 0.1 sat/vB.
inline constexpr unsigned int DEFAULT_INCREMENTAL_RELAY_FEE{100};
/** Default for -bytespersigop */
inline constexpr unsigned int DEFAULT_BYTES_PER_SIGOP{20};
/** Default for -permitbaremultisig */
inline constexpr bool DEFAULT_PERMIT_BAREMULTISIG{true};
/** The maximum number of witness stack items in a standard P2WSH script */
// COMMENT HOUSE: Limits on witness data and scriptSigs for standard spends.
// Larger ones are allowed by consensus, but this node will not relay them.
inline constexpr unsigned int MAX_STANDARD_P2WSH_STACK_ITEMS{100};
/** The maximum size in bytes of each witness stack item in a standard P2WSH script */
inline constexpr unsigned int MAX_STANDARD_P2WSH_STACK_ITEM_SIZE{80};
/** The maximum size in bytes of each witness stack item in a standard BIP 342 script (Taproot, leaf version 0xc0) */
inline constexpr unsigned int MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE{80};
/** The maximum size in bytes of a standard witnessScript */
inline constexpr unsigned int MAX_STANDARD_P2WSH_SCRIPT_SIZE{3600};
/** The maximum size of a standard ScriptSig */
inline constexpr unsigned int MAX_STANDARD_SCRIPTSIG_SIZE{1650};
/** Min feerate for defining dust.
 * Changing the dust limit changes which transactions are
 * standard and should be done with care and ideally rarely. It makes sense to
 * only increase the dust limit after prior releases were already not creating
 * outputs below the new threshold */
// COMMENT HOUSE: Dust (see GetDustThreshold() in policy/policy.cpp) is judged
// at 3,000 sat/kvB = 3 sat/vB.
inline constexpr unsigned int DUST_RELAY_TX_FEE{3000};
/** Default for -minrelaytxfee, minimum relay fee for transactions */
// COMMENT HOUSE: The lowest fee rate this node will accept into its mempool
// and pass on: 0.1 sat/vB. Transactions paying less are ignored, which makes
// flooding the network with junk cost money.
inline constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE{100};
/** Maximum number of transactions per cluster (default) */
// COMMENT HOUSE: Limits on groups of related unconfirmed transactions. If B
// spends an output of A, and both are in the mempool, they are related.
// A "cluster" is a whole group of related transactions (at most 64, and
// about 101,000 vB). Ancestors are the transactions a transaction depends
// on, and descendants are the ones that depend on it. Huge groups would make
// the mempool slow to manage.
inline constexpr unsigned int DEFAULT_CLUSTER_LIMIT{64};
/** Maximum size of cluster in virtual kilobytes */
inline constexpr unsigned int DEFAULT_CLUSTER_SIZE_LIMIT_KVB{101};
/** Default for -limitancestorcount, max number of in-mempool ancestors */
inline constexpr unsigned int DEFAULT_ANCESTOR_LIMIT{25};
/** Default for -limitdescendantcount, max number of in-mempool descendants */
inline constexpr unsigned int DEFAULT_DESCENDANT_LIMIT{25};
/** Default for -datacarrier */
// COMMENT HOUSE: "Data carrier" outputs are OP_RETURN outputs that just store
// data. By default this node relays them, up to 100,000 vB in total per
// transaction (MAX_STANDARD_TX_WEIGHT / 4).
inline constexpr bool DEFAULT_ACCEPT_DATACARRIER = true;
/**
 * Default setting for -datacarriersize in vbytes.
 */
inline constexpr unsigned int MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR;

/**
 * Maximum number of ephemeral dust outputs allowed.
 */
inline constexpr unsigned int MAX_DUST_OUTPUTS_PER_TX{1};

/**
 * Mandatory script verification flags that all new transactions must comply with for
 * them to be valid.
 *
 * Note that this does not affect consensus validity; see GetBlockScriptFlags()
 * for that.
 */
// COMMENT HOUSE: Script rules for new transactions (see script/interpreter.cpp):
//   - MANDATORY flags: rules from soft forks that are now consensus (P2SH,
//     strict signatures, time locks, SegWit, Taproot). Breaking these makes a
//     transaction invalid.
//   - STANDARD flags: the mandatory ones PLUS extra policy rules, mostly
//     against malleability, and to keep future upgrade features unused for
//     now. Breaking only these extras makes a transaction "non-standard" but
//     not invalid, so the peer that sent it is not punished.
inline constexpr script_verify_flags MANDATORY_SCRIPT_VERIFY_FLAGS{SCRIPT_VERIFY_P2SH |
                                                             SCRIPT_VERIFY_DERSIG |
                                                             SCRIPT_VERIFY_NULLDUMMY |
                                                             SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                             SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                                             SCRIPT_VERIFY_WITNESS |
                                                             SCRIPT_VERIFY_TAPROOT};

/**
 * Standard script verification flags that standard transactions will comply
 * with. However we do not ban/disconnect nodes that forward txs violating
 * the additional (non-mandatory) rules here, to improve forwards and
 * backwards compatibility.
 */
inline constexpr script_verify_flags STANDARD_SCRIPT_VERIFY_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                             SCRIPT_VERIFY_STRICTENC |
                                                             SCRIPT_VERIFY_MINIMALDATA |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                             SCRIPT_VERIFY_CLEANSTACK |
                                                             SCRIPT_VERIFY_MINIMALIF |
                                                             SCRIPT_VERIFY_NULLFAIL |
                                                             SCRIPT_VERIFY_LOW_S |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
                                                             SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
                                                             SCRIPT_VERIFY_CONST_SCRIPTCODE |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
                                                             SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE};

/** For convenience, standard but not mandatory verify flags. */
inline constexpr script_verify_flags STANDARD_NOT_MANDATORY_VERIFY_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS};

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
inline constexpr unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS{LOCKTIME_VERIFY_SEQUENCE};

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsStandard(const CScript& scriptPubKey, TxoutType& whichType);

/** Get the vout index numbers of all dust outputs */
std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate);

// Changing the default transaction version requires a two step process: first
// adapting relay policy by bumping TX_MAX_STANDARD_VERSION, and then later
// allowing the new transaction version in the wallet/RPC.
// COMMENT HOUSE: Standard transaction versions are 1, 2 and 3. Version 2 is
// needed for relative time locks (BIP 68), and version 3 ("TRUC",
// BIP 431) opts into stricter rules that make fee bumping more reliable.
inline constexpr decltype(CTransaction::version) TX_MIN_STANDARD_VERSION{1};
inline constexpr decltype(CTransaction::version) TX_MAX_STANDARD_VERSION{3};

/**
* Check for standard transaction types
* @return True if all outputs (scriptPubKeys) use only standard transaction forms
*/
bool IsStandardTx(const CTransaction& tx, const std::optional<unsigned>& max_datacarrier_bytes, bool permit_bare_multisig, const CFeeRate& dust_relay_fee, std::string& reason);
/**
 * Check for standard transaction types
 * @param[in] mapInputs       Map of previous transactions that have outputs we're spending
 * @returns valid TxValidationState if all inputs (scriptSigs) use only standard transaction forms else returns
 * invalid TxValidationState which states why the first invalid input is not standard
 */
TxValidationState ValidateInputsStandardness(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/**
* Check if the transaction is over standard P2WSH resources limit:
* 3600bytes witnessScript size, 80bytes per witness stack element, 100 witness stack elements
* These limits are adequate for multisignatures up to n-of-100 using OP_CHECKSIG, OP_ADD, and OP_EQUAL.
*
* Also enforce a maximum stack item size limit and no annexes for tapscript spends.
*/
bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/**
 * Check whether this transaction spends any witness program but P2A, including not-yet-defined ones.
 * May return `false` early for consensus-invalid transactions.
 */
bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts);

/** Compute the virtual transaction size (weight reinterpreted as bytes). */
// COMMENT HOUSE: Virtual size (vsize): weight / 4, rounded up, adjusted for
// signature-heavy transactions. Explained in policy/policy.cpp.
int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop);
int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop);
int64_t GetVirtualTransactionInputSize(const CTxIn& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop);

static inline int64_t GetVirtualTransactionSize(const CTransaction& tx)
{
    return GetVirtualTransactionSize(tx, 0, 0);
}

static inline int64_t GetVirtualTransactionInputSize(const CTxIn& tx)
{
    return GetVirtualTransactionInputSize(tx, 0, 0);
}

int64_t GetSigOpsAdjustedWeight(int64_t weight, int64_t sigop_cost, unsigned int bytes_per_sigop);

static inline FeePerVSize ToFeePerVSize(FeePerWeight feerate) { return {feerate.fee, (feerate.size + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR}; }

#endif // BITCOIN_POLICY_POLICY_H
