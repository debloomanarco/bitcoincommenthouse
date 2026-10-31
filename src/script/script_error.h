// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// A list of every reason a script can fail. When EvalScript() or
// VerifyScript() (script/interpreter.cpp) stops, it records one of these
// codes, so the node can say exactly WHY a spend was rejected. It works like
// the error codes in consensus/validation.h, but just for scripts.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_SCRIPT_SCRIPT_ERROR_H
#define BITCOIN_SCRIPT_SCRIPT_ERROR_H

#include <string>

typedef enum ScriptError_t
{
    // COMMENT HOUSE: The general results. OK means no error. EVAL_FALSE means the
    // script finished, but with false (or nothing) on top of the stack: for
    // example, a wrong signature. OP_RETURN means the script ran OP_RETURN,
    // which always fails.
    SCRIPT_ERR_OK = 0,
    SCRIPT_ERR_UNKNOWN_ERROR,
    SCRIPT_ERR_EVAL_FALSE,
    SCRIPT_ERR_OP_RETURN,
    SCRIPT_ERR_SCRIPTNUM,

    /* Max sizes */
    // COMMENT HOUSE: A safety limit from script/script.h was broken: script too
    // long, item too big, too many opcodes, too many stack items, or too many
    // signatures or keys in a multisig.
    SCRIPT_ERR_SCRIPT_SIZE,
    SCRIPT_ERR_PUSH_SIZE,
    SCRIPT_ERR_OP_COUNT,
    SCRIPT_ERR_STACK_SIZE,
    SCRIPT_ERR_SIG_COUNT,
    SCRIPT_ERR_PUBKEY_COUNT,

    /* Failed verify operations */
    // COMMENT HOUSE: A "VERIFY" opcode (like OP_EQUALVERIFY) found false and
    // stopped the script.
    SCRIPT_ERR_VERIFY,
    SCRIPT_ERR_EQUALVERIFY,
    SCRIPT_ERR_CHECKMULTISIGVERIFY,
    SCRIPT_ERR_CHECKSIGVERIFY,
    SCRIPT_ERR_NUMEQUALVERIFY,

    /* Logical/Format/Canonical errors */
    // COMMENT HOUSE: The script itself is broken: an unknown or disabled opcode,
    // an operation on a stack without enough items, or an OP_IF without its
    // OP_ENDIF.
    SCRIPT_ERR_BAD_OPCODE,
    SCRIPT_ERR_DISABLED_OPCODE,
    SCRIPT_ERR_INVALID_STACK_OPERATION,
    SCRIPT_ERR_INVALID_ALTSTACK_OPERATION,
    SCRIPT_ERR_UNBALANCED_CONDITIONAL,

    /* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
    // COMMENT HOUSE: A time lock in the script (OP_CHECKLOCKTIMEVERIFY or
    // OP_CHECKSEQUENCEVERIFY) is not over yet, or is badly formed.
    SCRIPT_ERR_NEGATIVE_LOCKTIME,
    SCRIPT_ERR_UNSATISFIED_LOCKTIME,

    /* Malleability */
    // COMMENT HOUSE: "Malleability" errors. These rules stop someone from changing
    // the bytes of a transaction (and so its txid) without changing what it
    // does, for example by writing a signature or a number in a different but
    // equivalent way. Many of them are policy rules (see policy/policy.cpp).
    SCRIPT_ERR_SIG_HASHTYPE,
    SCRIPT_ERR_SIG_DER,
    SCRIPT_ERR_MINIMALDATA,
    SCRIPT_ERR_SIG_PUSHONLY,
    SCRIPT_ERR_SIG_HIGH_S,
    SCRIPT_ERR_SIG_NULLDUMMY,
    SCRIPT_ERR_PUBKEYTYPE,
    SCRIPT_ERR_CLEANSTACK,
    SCRIPT_ERR_MINIMALIF,
    SCRIPT_ERR_SIG_NULLFAIL,

    /* softfork safeness */
    // COMMENT HOUSE: "Softfork safeness": features reserved for FUTURE upgrades,
    // such as unused OP_NOPs or unknown SegWit versions. Policy refuses to relay
    // them, so nobody's coins get stuck if a future upgrade gives them a new
    // meaning.
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_ERR_DISCOURAGE_OP_SUCCESS,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,

    /* segregated witness */
    // COMMENT HOUSE: Errors for SegWit (Phase 7) and Taproot (Phase 8) spends.
    SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH,
    SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY,
    SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH,
    SCRIPT_ERR_WITNESS_MALLEATED,
    SCRIPT_ERR_WITNESS_MALLEATED_P2SH,
    SCRIPT_ERR_WITNESS_UNEXPECTED,
    SCRIPT_ERR_WITNESS_PUBKEYTYPE,

    /* Taproot */
    SCRIPT_ERR_SCHNORR_SIG_SIZE,
    SCRIPT_ERR_SCHNORR_SIG_HASHTYPE,
    SCRIPT_ERR_SCHNORR_SIG,
    SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE,
    SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT,
    SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG,
    SCRIPT_ERR_TAPSCRIPT_MINIMALIF,
    SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY,

    /* Constant scriptCode */
    SCRIPT_ERR_OP_CODESEPARATOR,
    SCRIPT_ERR_SIG_FINDANDDELETE,

    // COMMENT HOUSE: Not a real error. Because enum values count up from 0, this
    // equals the number of error codes above it.
    SCRIPT_ERR_ERROR_COUNT
} ScriptError;

// COMMENT HOUSE: Turns an error code into readable text, for log messages.
std::string ScriptErrorString(ScriptError error);

#endif // BITCOIN_SCRIPT_SCRIPT_ERROR_H
