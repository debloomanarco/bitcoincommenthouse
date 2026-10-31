// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// It lists the SETTINGS of the Bitcoin protocol: how often blocks should
// come, when the block reward halves, when each rule upgrade switched on,
// and so on. Every node must use exactly the same settings, or nodes would
// disagree about which blocks are valid. That is why they are "consensus"
// parameters.
//
// This file only describes the list of settings (the Params struct). The
// actual numbers for the real Bitcoin network, and for the test networks,
// are filled in by kernel/chainparams.cpp.
//
// A word you will see a lot here: "BIP" means Bitcoin Improvement Proposal,
// a numbered public document describing a change to Bitcoin. For example,
// BIP 141 is SegWit.
#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <script/verify_flags.h>
#include <uint256.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <vector>

// COMMENT HOUSE: A namespace is a "family name" for code. Everything inside is
// written in full as Consensus::Params, Consensus::BIP9Deployment and so on,
// so these names cannot clash with names elsewhere.
namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 * Consensus changes for which the new rules are enforced from genesis are not listed here.
 */
// COMMENT HOUSE: Upgrades to Bitcoin's rules are called "deployments".
// Once an upgrade has been active for years, its exact switch-on block
// number (its "height") is simply written into the code. The upgrade is then
// called "buried", because it is buried deep in the chain's history.
// These are the buried ones:
//   - HEIGHTINCB (BIP 34): each block's coinbase must contain its height.
//   - CLTV (BIP 65):       coins can be locked until a certain time or block.
//   - DERSIG (BIP 66):     signatures must use one strict, standard format.
//   - CSV (BIP 68, 112, 113): coins can be locked for a period of time after
//                          they are received ("relative" time locks).
//   - SEGWIT (BIP 141):    Segregated Witness (covered in a later phase).
// An enum is a list of named values. They start at the smallest number an
// int16_t can hold, so they can never be confused with DeploymentPos below.
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    // SCRIPT_VERIFY_WITNESS is enforced from genesis, but the check for downloading
    // missing witness data is not. BIP 147 also relies on hardcoded activation height.
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

// COMMENT HOUSE: Upgrades that are NOT buried, and still use the signalling
// process described below (BIP9Deployment). Right now there is only
// TESTDUMMY, a fake upgrade used to test the process.
// MAX_VERSION_BITS_DEPLOYMENTS is not a real upgrade. It is a trick: because
// enum values count up from 0, it equals the number of entries before it.
enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    // Removing an entry may require bumping MinBIP9WarningHeight.
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
// COMMENT HOUSE: BIP9Deployment, how miners vote on a new rule (BIP 9).
// Miners signal "I'm ready for this upgrade" by setting one bit (one
// on/off switch) in the nVersion field of the block header. Blocks are
// counted in groups of 2016 (about two weeks). If enough blocks in one
// group signal (by default 1916 of 2016, which is 95%), the upgrade "locks
// in" and switches on shortly after. If that never happens before nTimeout,
// the attempt fails.
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};
    /** Period of blocks to check signalling in (usually retarget period, ie params.DifficultyAdjustmentInterval()) */
    uint32_t period{2016};
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t threshold{1916};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Parameters that influence chain consensus.
 */
// COMMENT HOUSE: Params, the full list of protocol settings.
// The most important ones for beginners:
//   - hashGenesisBlock:        the hash of the very first block.
//   - nSubsidyHalvingInterval: how many blocks between reward halvings
//                              (210,000 on the real network, about 4 years).
//   - BIP34Height ... SegwitHeight: the block heights where each buried
//                              upgrade (see BuriedDeployment) switched on.
//   - powLimit:                the EASIEST difficulty ever allowed.
//   - nPowTargetSpacing:       the target time between blocks (10 minutes).
//   - nPowTargetTimespan:      how often difficulty is adjusted (2 weeks).
//   - nMinimumChainWork:       a safety check: a chain with less total
//                              mining work than this is ignored, so a
//                              new node cannot be fooled by a short fake
//                              chain.
//   - defaultAssumeValid:      a known-good block. To save time, a new node
//                              skips checking SIGNATURES in blocks before
//                              it, but still checks every other rule.
// Mining and difficulty are explained in pow.cpp, a later phase.
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, script_verify_flags> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV, segwit and taproot activations. */
    int MinBIP9WarningHeight;
    std::array<BIP9Deployment,MAX_VERSION_BITS_DEPLOYMENTS> vDeployments;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    /**
      * Enforce BIP94 timewarp attack mitigation. On testnet4 this also enforces
      * the block storm mitigation.
      */
    bool enforce_BIP94;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    // COMMENT HOUSE: How many blocks between difficulty adjustments: two weeks
    // divided by 10 minutes = 2016 blocks.
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    // COMMENT HOUSE: Given a buried upgrade's name, returns the block height where
    // it switched on. A "switch" statement picks one "case" based on a value.
    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
