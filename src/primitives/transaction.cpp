// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This file holds the code ("definitions") for the functions that
// primitives/transaction.h only announced. If you have not read
// transaction.h yet, read it first: it explains inputs, outputs, outpoints
// and the difference between CTransaction and CMutableTransaction.
//
// The most important parts here are:
//   - how a transaction's ID (txid) is calculated, and
//   - GetValueOut(), which adds up the outputs and refuses impossible totals.
// Most of the rest are ToString() functions that turn objects into readable
// text for logs and debugging. They do not affect any rules.
#include <primitives/transaction.h>

#include <consensus/amount.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <primitives/transaction_identifier.h>
#include <script/script.h>
#include <serialize.h>
#include <tinyformat.h>

#include <algorithm>
#include <cassert>
#include <span>
#include <stdexcept>

// COMMENT HOUSE: ToString() makes a short, human-readable description of the
// outpoint, like "COutPoint(4a5e1e4baa, 0)". substr(0,10) keeps only the
// first 10 characters of the long transaction ID so log lines stay short.
std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

// COMMENT HOUSE: Two constructors (ways to create) a CTxIn. The first one takes
// a ready-made COutPoint. The second takes the transaction ID and output
// number separately and builds the COutPoint itself. Both just copy the
// values they are given into the input's fields.
CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(Txid hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

// COMMENT HOUSE: A readable description of an input. If the outpoint is
// "null", this is a coinbase input (it creates new coins instead of spending
// old ones), so it is labeled "coinbase". nSequence is only shown when it is
// not the default SEQUENCE_FINAL value, to keep the text short.
// HexStr() turns raw bytes into hexadecimal text (0-9 and a-f).
std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ')';
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

// COMMENT HOUSE: A readable description of an output. nValue is stored in
// satoshis, so nValue / COIN gives the whole bitcoins and nValue % COIN
// (the remainder) gives the leftover satoshis. %08d pads that remainder to
// 8 digits, so 150000000 satoshis prints as "1.50000000".
std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

// COMMENT HOUSE: Two ways to create a CMutableTransaction (the editable kind).
// The first makes an empty one with the current default version and a lock
// time of 0 (meaning "no time lock"). The second copies an existing,
// finished CTransaction so it can be edited, for example to add a signature.
CMutableTransaction::CMutableTransaction() : version{CTransaction::CURRENT_VERSION}, nLockTime{0} {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), version{tx.version}, nLockTime{tx.nLockTime} {}

// COMMENT HOUSE: GetHash() calculates the transaction ID (txid).
// HashWriter turns the transaction into bytes and runs them through
// double SHA-256 (see hash.h), producing a 32-byte fingerprint.
// TX_NO_WITNESS means the witness data (signatures stored separately since
// SegWit, explained in a later phase) is left OUT. That is on purpose: if the
// signatures were part of the txid, someone could slightly change a
// signature's bytes without making it invalid and change the txid. This
// problem is called "transaction malleability". An editable transaction
// recalculates its hash every time you ask, because it might have changed.
Txid CMutableTransaction::GetHash() const
{
    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS(*this)).GetHash());
}

// COMMENT HOUSE: Does any input carry witness data? std::any_of goes through
// every input in vin and returns true as soon as one of them has a
// non-empty scriptWitness. The [](...) { ... } part is a "lambda", a tiny
// unnamed function written right where it is used.
bool CTransaction::ComputeHasWitness() const
{
    return std::any_of(vin.begin(), vin.end(), [](const auto& input) {
        return !input.scriptWitness.IsNull();
    });
}

// COMMENT HOUSE: The same txid calculation as CMutableTransaction::GetHash()
// above. A CTransaction cannot change, so it only needs to do this once, when
// it is created, and then stores the answer in the hash field.
Txid CTransaction::ComputeHash() const
{
    return Txid::FromUint256((HashWriter{} << TX_NO_WITNESS(*this)).GetHash());
}

// COMMENT HOUSE: The wtxid ("witness transaction ID") is a second fingerprint
// that DOES include the witness data (TX_WITH_WITNESS). If the transaction has
// no witness data at all, the wtxid is simply the same as the txid, so it
// reuses that value instead of hashing again.
Wtxid CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return Wtxid::FromUint256(hash.ToUint256());
    }

    return Wtxid::FromUint256((HashWriter{} << TX_WITH_WITNESS(*this)).GetHash());
}

// COMMENT HOUSE: This is how an editable CMutableTransaction becomes a
// finished CTransaction. It copies the inputs, outputs, version and lock
// time, then calculates and stores the witness flag, txid and wtxid once.
// The order matters: the wtxid calculation uses the witness flag and txid.
// The second version does the same, but std::move "moves" the inputs and
// outputs instead of copying them, which is faster when the editable
// transaction is no longer needed.
CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), version{tx.version}, nLockTime{tx.nLockTime}, m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), version{tx.version}, nLockTime{tx.nLockTime}, m_has_witness{ComputeHasWitness()}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

// COMMENT HOUSE: GetValueOut() adds up the amounts of all outputs.
// It is careful about impossible numbers: for each output it checks, using
// MoneyRange() from consensus/amount.h, that the output's amount and the
// running total both stay between 0 and 21 million bitcoins. If not, it
// throws an error. This matters because in 2010 a bug let someone create a
// transaction whose outputs were so large that adding them "wrapped around"
// like a car's odometer, creating about 184 billion bitcoins. Checks like this
// make sure that can never happen again. assert() is a final safety check that
// stops the program if something that "can't happen" happens anyway.
CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

// COMMENT HOUSE: The total size of the transaction in bytes, including witness
// data. Size matters because blocks have limited space, and fees are usually
// calculated per byte.
unsigned int CTransaction::ComputeTotalSize() const
{
    return ::GetSerializeSize(TX_WITH_WITNESS(*this));
}

// COMMENT HOUSE: A readable, multi-line description of the whole transaction:
// a summary line, then one line per input, one line per input's witness, and
// one line per output.
std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%u, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        version,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}
