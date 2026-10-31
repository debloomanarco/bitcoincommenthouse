// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// It announces CheckTransaction(), whose code and full explanation are in
// consensus/tx_check.cpp: the first, "context-free" checks every
// transaction must pass. As the developer comment below says, these checks
// need nothing but the transaction itself. Checks that need the UTXO set or
// the chain belong in consensus/tx_verify.h instead.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_CONSENSUS_TX_CHECK_H
#define BITCOIN_CONSENSUS_TX_CHECK_H

/**
 * Context-independent transaction checking code that can be called outside the
 * bitcoin server and doesn't depend on chain or mempool state. Transaction
 * verification code that does call server functions or depend on server state
 * belongs in tx_verify.h/cpp instead.
 */

// COMMENT HOUSE: Forward declarations: they only say "these types exist", so
// this small file does not have to include their full definitions.
class CTransaction;
class TxValidationState;

bool CheckTransaction(const CTransaction& tx, TxValidationState& state);

#endif // BITCOIN_CONSENSUS_TX_CHECK_H
