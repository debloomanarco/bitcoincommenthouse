// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This file describes what a Bitcoin TRANSACTION looks like as data. A
// transaction is how bitcoin moves: it takes coins from earlier transactions
// and assigns them to new owners. This is one of the most important files for
// understanding Bitcoin.
//
// The big idea: Bitcoin has no "account balances". Instead, coins exist as
// "outputs" of earlier transactions, like individual bills in a wallet. To pay
// someone, a transaction:
//   - lists INPUTS: which existing bills (earlier outputs) it is spending, with
//     proof that the spender is allowed to spend them, and
//   - creates OUTPUTS: new bills, each with an amount and a lock saying who can
//     spend it next.
// Like paying cash, you usually cannot hand over exactly the right bills, so a
// transaction often creates one output for the person being paid and one
// "change" output back to yourself. An output that has not been spent yet is
// called a UTXO ("unspent transaction output").
//
// There is no "fee" field. The fee is whatever is left over: the total value of
// the inputs minus the total value of the outputs. Miners collect it.
//
// The main pieces, in the order they appear:
//   1. COutPoint            - points to one specific earlier output
//   2. CTxIn                - an input: which output it spends, plus proof
//   3. CTxOut               - an output: an amount and a locking script
//   4. Serialize/Unserialize functions - how a transaction is turned into
//                             bytes and back
//   5. CTransaction         - a finished transaction, not meant to be changed
//   6. CMutableTransaction  - a transaction that is still being built/edited
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

// COMMENT HOUSE: Other files this one needs. consensus/amount.h gives CAmount
// (money in satoshis), script/script.h gives CScript (Bitcoin's small
// programming language, used for the "locks" on outputs),
// primitives/transaction_identifier.h gives Txid and Wtxid (transaction IDs),
// and serialize.h gives the tools for turning objects into bytes.
#include <attributes.h>
#include <consensus/amount.h>
#include <primitives/transaction_identifier.h> // IWYU pragma: export
#include <script/script.h>
#include <serialize.h>

#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <memory>
#include <numeric>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

// COMMENT HOUSE: COutPoint, "which earlier output am I talking about?"
// An outpoint names exactly one output in the whole history of Bitcoin, using
// two pieces of information:
//   - hash: the transaction ID (Txid) of the transaction that created it, and
//   - n:    which output of that transaction it is, counting from 0.
// So "output 1 of transaction 4a5e1e..." is an outpoint. It is like saying
// "the second bill in envelope number 4a5e1e...".
/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    Txid hash;
    uint32_t n;

    // COMMENT HOUSE: NULL_INDEX is the largest number a uint32_t can hold
    // (4,294,967,295). It is used as a special "points to nothing" value. A
    // "null" outpoint (all-zero hash and n = NULL_INDEX) appears in exactly one
    // place: the single input of a coinbase transaction, which creates new
    // coins instead of spending old ones (see IsCoinBase() further down).
    static constexpr uint32_t NULL_INDEX = std::numeric_limits<uint32_t>::max();

    COutPoint(): n(NULL_INDEX) { }
    COutPoint(const Txid& hashIn, uint32_t nIn): hash(hashIn), n(nIn) { }

    // COMMENT HOUSE: SERIALIZE_METHODS / READWRITE describe how to turn this
    // object into bytes (to save or send it) and back: first the hash, then n.
    // You will see this pattern on most data types in Bitcoin Core.
    SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.hash, obj.n); }

    void SetNull() { hash.SetNull(); n = NULL_INDEX; }
    bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }

    // COMMENT HOUSE: operator< and operator== define what < and == mean for
    // outpoints, so they can be sorted and compared. std::tie compares the hash
    // first, and only if the hashes are equal does it compare n.
    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return std::tie(a.hash, a.n) < std::tie(b.hash, b.n);
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    std::string ToString() const;
};

// COMMENT HOUSE: CTxIn, a transaction INPUT.
// An input says "I am spending this earlier output, and here is my proof that
// I am allowed to." It contains:
//   - prevout:       the COutPoint of the output being spent.
//   - scriptSig:     the "unlocking script": data (usually a digital signature)
//                    that satisfies the lock on the output being spent.
//   - nSequence:     a number with several uses, explained by the constants
//                    below (mainly time locks).
//   - scriptWitness: "witness" data. Since the SegWit upgrade (BIP 141), the
//                    signatures for many kinds of outputs go here instead of in
//                    scriptSig. It is stored in a separate section of the
//                    transaction (see the serialization format further down).
// Notice that an input does NOT contain an amount. The amount is already
// written in the output being spent, so the node looks it up there.
/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScriptWitness scriptWitness; //!< Only serialized through CTransaction

    // COMMENT HOUSE: Time locks and nSequence.
    // Bitcoin lets a transaction say "I may not be included in a block until
    // later". There are two kinds:
    //   - Absolute time lock: the transaction's nLockTime field (see
    //     CTransaction below) says "not before block number X" or "not before
    //     date X".
    //   - Relative time lock (BIP 68): an input's nSequence can say "not until
    //     N blocks (or N x 512 seconds) after the output I spend was
    //     confirmed".
    // The constants below are the special values and "flags" (single bits that
    // act as on/off switches) that decide how nSequence is read. 0xffffffff is
    // hex for the largest 32-bit number: all 32 bits switched on.
    /**
     * Setting nSequence to this value for every input in a transaction
     * disables nLockTime/IsFinalTx().
     * It fails OP_CHECKLOCKTIMEVERIFY/CheckLockTime() for any input that has
     * it set (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static constexpr uint32_t SEQUENCE_FINAL{0xffffffff};
    /**
     * This is the maximum sequence number that enables both nLockTime and
     * OP_CHECKLOCKTIMEVERIFY (BIP 65).
     * It has SEQUENCE_LOCKTIME_DISABLE_FLAG set (BIP 68/112).
     */
    static constexpr uint32_t MAX_SEQUENCE_NONFINAL{SEQUENCE_FINAL - 1};

    // COMMENT HOUSE: 1U << 31 is a number with only bit 31 (the highest bit)
    // switched on.
    // Below flags apply in the context of BIP 68. BIP 68 requires the tx
    // version to be set to 2, or higher.
    /**
     * If this flag is set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time.
     * It skips SequenceLocks() for any input that has it set (BIP 68).
     * It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
     * it set (BIP 112).
     */
    static constexpr uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG{1U << 31};

    // COMMENT HOUSE: Bit 22 chooses the unit of a relative time lock: off =
    // blocks, on = units of 512 seconds (about 8.5 minutes).
    /**
     * If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static constexpr uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG{1 << 22};

    // COMMENT HOUSE: A "mask" picks out certain bits. 0x0000ffff keeps only the
    // lowest 16 bits, where the length of the relative time lock is stored, and
    // zeroes the rest.
    /**
     * If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static constexpr uint32_t SEQUENCE_LOCKTIME_MASK{0x0000ffff};

    /**
     * In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static constexpr int SEQUENCE_LOCKTIME_GRANULARITY{9};

    // COMMENT HOUSE: Constructors: the ways to create an input. By default
    // nSequence is SEQUENCE_FINAL, meaning "no time lock". The "=CScript()"
    // parts are default values used when the caller does not supply them.
    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(Txid hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    // COMMENT HOUSE: Only prevout, scriptSig and nSequence are written here.
    // The witness is written separately by SerializeTransaction() below, which
    // is what the "Only serialized through CTransaction" note above refers to.
    SERIALIZE_METHODS(CTxIn, obj) { READWRITE(obj.prevout, obj.scriptSig, obj.nSequence); }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    std::string ToString() const;
};

// COMMENT HOUSE: CTxOut, a transaction OUTPUT: a new "bill" that someone can
// spend later.
//   - nValue:       how much it is worth, in satoshis (see consensus/amount.h).
//   - scriptPubKey: the "locking script". It states the condition for spending
//                   this output, most often "a valid signature from the owner
//                   of this key". Despite the name, it usually holds a HASH of
//                   a public key (or of a script), not the key itself.
// Once created, an output stays unspent until some later transaction's input
// points to it with a COutPoint. Each output can only be spent once.
/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    SERIALIZE_METHODS(CTxOut, obj) { READWRITE(obj.nValue, obj.scriptPubKey); }

    // COMMENT HOUSE: A "null" output is marked by the impossible value nValue =
    // -1. It means "empty / not set", not a real output.
    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

// COMMENT HOUSE: Two ways of turning a transaction into bytes: TX_WITH_WITNESS
// includes the witness (SegWit) data, TX_NO_WITNESS leaves it out. Both are
// needed because the transaction ID (txid) is calculated WITHOUT the witness
// data (see ComputeHash() in src/primitives/transaction.cpp).
struct TransactionSerParams {
    const bool allow_witness;
    SER_PARAMS_OPFUNC
};
inline constexpr TransactionSerParams TX_WITH_WITNESS{.allow_witness = true};
inline constexpr TransactionSerParams TX_NO_WITNESS{.allow_witness = false};

// COMMENT HOUSE: Serialization: how a transaction looks as raw bytes. Before
// nodes can save or send a transaction, it has to be turned into a row of bytes
// ("serialized"), in exactly the same way on every computer. The original
// comment below lists the order.
//
// The "extended" format was added by SegWit (BIP 144) to carry witness data.
// The trick: right after the version comes a 0x00 byte (the "dummy"), which in
// the basic format would mean "this transaction has zero inputs". A real
// transaction must have at least one input (src/consensus/tx_check.cpp rejects
// transactions with none), so a valid basic-format transaction can never start
// that way. That means a 0x00 followed by a flags byte can only mean "extended
// format", and the two formats can never be confused.
/**
 * Basic transaction serialization format:
 * - uint32_t version
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - uint32_t version
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CScriptWitness scriptWitness; (deserialized into CTxIn)
 * - uint32_t nLockTime
 */
template<typename Stream, typename TxType>
// COMMENT HOUSE: UnserializeTransaction reads a transaction back from bytes.
// Step by step:
//   1. Read the version.
//   2. Try to read the list of inputs. If it comes out empty, that was really
//      the 0x00 dummy byte, so read the flags byte next. If flags is not 0,
//      read the real inputs and outputs.
//   3. Otherwise, it was a normal transaction: read the outputs.
//   4. If flag bit 1 is set, read one witness for every input. A transaction
//      that sets this flag but has only empty witnesses is rejected, so every
//      transaction has exactly one valid way to be written as bytes.
//   5. Any other flag bits are unknown, so the data is rejected.
//   6. Finally, read nLockTime.
// "s >> x" means "read x from the stream s". "flags ^= 1" switches bit 1 off
// again, so step 5 can check whether any OTHER bits were set.
void UnserializeTransaction(TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;

    s >> tx.version;
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) {
            s >> tx.vin;
            s >> tx.vout;
        }
    } else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
        if (!tx.HasWitness()) {
            /* It's illegal to encode witnesses when all witness stacks are empty. */
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
}

template<typename Stream, typename TxType>
// COMMENT HOUSE: SerializeTransaction is the opposite: it writes a transaction
// as bytes. It uses the extended format (dummy + flags + witnesses) only when
// there is witness data to write and witnesses are allowed; otherwise it writes
// the basic format, which older software can read. "s << x" means "write x".
void SerializeTransaction(const TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;

    s << tx.version;
    unsigned char flags = 0;
    // Consistency check
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (flags) {
        /* Use extended format in case witnesses are to be serialized. */
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;
    if (flags & 1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    s << tx.nLockTime;
}

template<typename TxType>
// COMMENT HOUSE: CalculateOutputValue adds up the values of all outputs.
// std::accumulate goes through the list keeping a running total, starting from
// 0. Unlike GetValueOut() below, it does no range checks.
inline CAmount CalculateOutputValue(const TxType& tx)
{
    return std::accumulate(tx.vout.cbegin(), tx.vout.cend(), CAmount{0}, [](CAmount sum, const auto& txout) { return sum + txout.nValue; });
}

// COMMENT HOUSE: Options for CTransaction::Equals() below: whether to also
// compare the scriptSig and witness (signature) data when comparing two
// transactions.
struct EqualsOptions {
    bool include_script_sig{true};
    bool include_witness_data{true};
};


// COMMENT HOUSE: CTransaction, a finished transaction.
// This is the form used for transactions that are sent across the network and
// stored in blocks. It holds:
//   - vin:       the list of inputs (a std::vector is a list that can grow).
//   - vout:      the list of outputs.
//   - version:   a version number. Version 2 or higher is needed to use the
//                relative time locks (BIP 68) explained above.
//   - nLockTime: the absolute time lock. 0 means no lock. Values below
//                500,000,000 are read as a block number, larger values as a
//                time (seconds since 1 January 1970). See IsFinalTx() in
//                src/consensus/tx_verify.cpp and LOCKTIME_THRESHOLD in
//                src/script/script.h.
//
// Why are the fields "const" (unchangeable)? A transaction's ID is a hash of
// its contents, and it is worked out once, when the CTransaction is created,
// then saved ("cached") so it never has to be recomputed. If the contents could
// change afterwards, the saved ID would become wrong. To change a transaction,
// you copy it into a CMutableTransaction (below), edit that, and create a new
// CTransaction from it. (The original comment inside the class explains the
// fine print: a few special operations do replace a CTransaction's contents,
// but they always recompute the ID too, so it stays correct.)
/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    // Default transaction version.
    static constexpr uint32_t CURRENT_VERSION{2};

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t version;
    const uint32_t nLockTime;

private:
    // COMMENT HOUSE: "Memory only": these are worked out from the transaction's
    // contents and kept in memory for speed, but never saved or sent, because
    // anyone can recompute them.
    //   - hash (Txid):            the transaction ID. Double SHA-256 of the
    //                             transaction WITHOUT witness data.
    //   - m_witness_hash (Wtxid): the "witness transaction ID". The same, but
    //                             WITH witness data.
    // Leaving the witness out of the txid was a key SegWit fix: signatures can
    // be changed slightly by others without becoming invalid ("malleability"),
    // and because signatures for SegWit inputs live in the witness, changing
    // them no longer changes the txid.
    /** Memory only. */
    const bool m_has_witness;
    const Txid hash;
    const Wtxid m_witness_hash;

    Txid ComputeHash() const;
    Wtxid ComputeWitnessHash() const;

    bool ComputeHasWitness() const;

public:
    /** Convert a CMutableTransaction into a CTransaction. */
    explicit CTransaction(const CMutableTransaction& tx);
    explicit CTransaction(CMutableTransaction&& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    /** This deserializing constructor is provided instead of an Unserialize method.
     *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    CTransaction(deserialize_type, const TransactionSerParams& params, Stream& s) : CTransaction(CMutableTransaction(deserialize, params, s)) {}
    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    // COMMENT HOUSE: GetHash() returns the txid; GetWitnessHash() returns the
    // wtxid. Both just hand back the cached value, so they are very fast.
    const Txid& GetHash() const LIFETIMEBOUND { return hash; }
    const Wtxid& GetWitnessHash() const LIFETIMEBOUND { return m_witness_hash; };

    // COMMENT HOUSE: GetValueOut() adds up all output values, and stops with an
    // error if any value or the running total goes outside MoneyRange()
    // (consensus/amount.h). This protects against the kind of overflow bug
    // described there.
    // Return sum of txouts.
    CAmount GetValueOut() const;

    /**
     * Calculate the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int ComputeTotalSize() const;

    // COMMENT HOUSE: IsCoinBase() asks: is this the special "coinbase"
    // transaction? Every block starts with one coinbase transaction. It is how
    // new bitcoins are created: it pays the miner the block reward plus the
    // fees of all other transactions in the block. Since it creates coins
    // rather than spending earlier ones, it has exactly one input, and that
    // input's prevout is null (points to nothing). New coins from a coinbase
    // cannot be spent until 100 more blocks have been added (COINBASE_MATURITY
    // in src/consensus/consensus.h).
    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    // COMMENT HOUSE: Equals() compares two transactions field by field. With
    // the options, it can ignore signature data, for example to check whether
    // two transactions are "the same payment" even if they were signed
    // differently.
    bool Equals(const CTransaction& other, const EqualsOptions opts = {}) const
    {
        return nLockTime == other.nLockTime &&
            version == other.version &&
            vout == other.vout &&
            std::ranges::equal(vin, other.vin, [&opts](const CTxIn& self, const CTxIn& other) {
                return self.prevout == other.prevout &&
                    self.nSequence == other.nSequence &&
                    (opts.include_script_sig ? self.scriptSig == other.scriptSig : true) &&
                    (opts.include_witness_data ? self.scriptWitness.stack == other.scriptWitness.stack : true);
            });
    }

    std::string ToString() const;

    bool HasWitness() const { return m_has_witness; }
};

// COMMENT HOUSE: CMutableTransaction, the "editable" version. It has the same
// four fields as CTransaction, but they are not const, so code can build a
// transaction step by step: add inputs, add outputs, then sign. When it is
// ready, it is turned into a CTransaction, which computes and caches the IDs.
// Wallets and tests use this a lot.
/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t version;
    uint32_t nLockTime;

    explicit CMutableTransaction();
    explicit CMutableTransaction(const CTransaction& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        UnserializeTransaction(*this, s, s.template GetParams<TransactionSerParams>());
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, const TransactionSerParams& params, Stream& s) {
        UnserializeTransaction(*this, s, params);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    // COMMENT HOUSE: Because the fields can change, there is nothing cached
    // here: GetHash() recalculates the txid every time it is called.
    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    Txid GetHash() const;

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
};

// COMMENT HOUSE: CTransactionRef: a shared "reference" to a transaction.
// A popular transaction might be needed in many places at once (the mempool,
// a block, messages to several peers). Instead of copying it each time, Bitcoin
// Core keeps one copy and passes around a std::shared_ptr: a pointer that
// counts how many places are using the object and deletes it automatically when
// the last one is done. MakeTransactionRef() creates one.
typedef std::shared_ptr<const CTransaction> CTransactionRef;
template <typename Tx> static inline CTransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const CTransaction>(std::forward<Tx>(txIn)); }

// COMMENT HOUSE: This blocks the standard "hash" for CTransactionRef. Without
// it, a CTransactionRef could be used as a key in standard lookup tables, but
// it would be looked up by its memory address, so two copies of the same
// transaction would count as different. Making that impossible ("= delete")
// forces programmers to choose a proper way, such as using the txid.
namespace std {
/** Disable default std::hash for CTransactionRef to prevent accidentally
 *  comparing by pointer. Use CTransactionRefHash or provide a custom
 *  hasher. */
template <>
struct hash<CTransactionRef> {
    hash() = delete;
    // Belt-and-suspenders, already implied by the above.
    size_t operator()(const CTransactionRef&) const = delete;
};
} // namespace std

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
