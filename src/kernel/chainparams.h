// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// It describes CChainParams, the "settings card" for one Bitcoin network
// (mainnet, testnet, signet or regtest). The actual numbers are filled in
// by kernel/chainparams.cpp, so read that file for the genesis block, magic
// bytes, ports and address prefixes. A CChainParams holds:
//   - the consensus rules' numbers (Consensus::Params, consensus/params.h),
//   - networking details (magic bytes, default port, DNS seeds),
//   - address formats (base58 prefixes, the bech32 "bc" part),
//   - the genesis block, and
//   - assumeutxo snapshots and other start-up helpers.
// The rest of the program asks Params() for these, so the same code can run
// on any network.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_KERNEL_CHAINPARAMS_H
#define BITCOIN_KERNEL_CHAINPARAMS_H

#include <consensus/params.h>
#include <kernel/messagestartchars.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/hash_type.h>
#include <util/vector.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

struct AssumeutxoHash : public BaseHash<uint256> {
    explicit AssumeutxoHash(const uint256& hash) : BaseHash(hash) {}
};

/**
 * Holds configuration for use during UTXO snapshot load and validation. The contents
 * here are security critical, since they dictate which UTXO snapshots are recognized
 * as valid.
 */
// COMMENT HOUSE: AssumeutxoData: a trusted fingerprint of the full UTXO set
// (coins.h) at a given block height. A new node can load a downloaded copy
// of the UTXO set, check it against this hash, and start using the chain
// quickly, while it checks the full history in the background.
struct AssumeutxoData {
    int height;

    //! The expected hash of the deserialized UTXO set.
    AssumeutxoHash hash_serialized;

    //! Used to populate the m_chain_tx_count value, which is used during BlockManager::LoadBlockIndex().
    //!
    //! We need to hardcode the value here because this is computed cumulatively using block data,
    //! which we do not necessarily have at the time of snapshot load.
    uint64_t m_chain_tx_count;

    //! The hash of the base block for this snapshot. Used to refer to assumeutxo data
    //! prior to having a loaded blockindex.
    uint256 blockhash;
};

/**
 * Holds various statistics on transactions within a chain. Used to estimate
 * verification progress during chain sync.
 *
 * See also: CChainParams::TxData, GuessVerificationProgress.
 */
// COMMENT HOUSE: ChainTxData: rough transaction counts, used only to show how
// far along a new node is while it downloads the chain.
struct ChainTxData {
    int64_t nTime;    //!< UNIX timestamp of last known number of transactions
    uint64_t tx_count; //!< total number of transactions between genesis and that timestamp
    double dTxRate;   //!< estimated number of transactions per second after that timestamp
};

//! Configuration for headers sync memory usage.
// COMMENT HOUSE: Settings for downloading block HEADERS safely before the
// full blocks. They limit memory use if a peer sends a long fake chain of
// headers.
struct HeadersSyncParams {
    //! Distance in blocks between header commitments.
    size_t commitment_period{0};
    //! Minimum number of validated headers to accumulate in the redownload
    //! buffer before feeding them into the permanent block index.
    size_t redownload_buffer_size{0};
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system.
 */
// COMMENT HOUSE: CChainParams, the settings card. The functions in the
// "public:" part just hand out the stored values (GetConsensus(),
// GetDefaultPort(), GenesisBlock(), Bech32HRP() and so on). The values
// themselves are in the "protected:" part at the bottom.
class CChainParams
{
public:
    // COMMENT HOUSE: The kinds of base58 data that each have their own version
    // prefix (see base58Prefixes in kernel/chainparams.cpp and key_io.cpp):
    // P2PKH addresses, P2SH addresses, private keys (WIF), and extended
    // public and private keys (xpub/xprv).
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        MAX_BASE58_TYPES
    };

    const Consensus::Params& GetConsensus() const { return consensus; }
    const MessageStartChars& MessageStart() const { return pchMessageStart; }
    uint16_t GetDefaultPort() const { return nDefaultPort; }
    std::vector<int> GetAvailableSnapshotHeights() const;

    const CBlock& GenesisBlock() const { return genesis; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** If this chain is exclusively used for testing */
    bool IsTestChain() const { return m_chain_type != ChainType::MAIN; }
    /** If this chain allows time to be mocked */
    bool IsMockableChain() const { return m_is_mockable_chain; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /** Minimum free space (in GiB) needed for data directory */
    uint64_t AssumedBlockchainSize() const { return m_assumed_blockchain_size; }
    /** Minimum free space (in GiB) needed for data directory when pruned; Does not include prune target*/
    uint64_t AssumedChainStateSize() const { return m_assumed_chain_state_size; }
    /** Whether it is possible to mine blocks on demand (no retargeting) */
    bool MineBlocksOnDemand() const { return consensus.fPowNoRetargeting; }
    /** Return the chain type string */
    std::string GetChainTypeString() const { return ChainTypeToString(m_chain_type); }
    /** Return the chain type */
    ChainType GetChainType() const { return m_chain_type; }
    /** Return the list of hostnames to look up for DNS seeds */
    const std::vector<std::string>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::string& Bech32HRP() const { return bech32_hrp; }
    const std::string& SilentPaymentsHRP() const { return silent_payments_hrp; }
    const std::vector<uint8_t>& FixedSeeds() const { return vFixedSeeds; }
    const HeadersSyncParams& HeadersSync() const { return m_headers_sync_params; }

    std::optional<AssumeutxoData> AssumeutxoForHeight(int height) const
    {
        return FindFirst(m_assumeutxo_data, [&](const auto& d) { return d.height == height; });
    }
    std::optional<AssumeutxoData> AssumeutxoForBlockhash(const uint256& blockhash) const
    {
        return FindFirst(m_assumeutxo_data, [&](const auto& d) { return d.blockhash == blockhash; });
    }

    const ChainTxData& TxData() const { return chainTxData; }

    /**
     * VersionBitsParameters holds activation parameters
     */
    // COMMENT HOUSE: Options that test networks can use to change when upgrades
    // switch on (see ApplyDeploymentOptions() in kernel/chainparams.cpp).
    struct VersionBitsParameters {
        int64_t start_time;
        int64_t timeout;
        int min_activation_height;
    };

    struct DeploymentOptions {
        std::unordered_map<Consensus::DeploymentPos, VersionBitsParameters> version_bits_parameters{};
        std::unordered_map<Consensus::BuriedDeployment, int> activation_heights{};
    };

    /**
     * SigNetOptions holds configurations for creating a signet CChainParams.
     */
    struct SigNetOptions {
        DeploymentOptions dep_opts{};
        std::optional<std::vector<uint8_t>> challenge{};
        std::optional<std::vector<std::string>> seeds{};
    };

    /**
     * RegTestOptions holds configurations for creating a regtest CChainParams.
     */
    struct RegTestOptions {
        DeploymentOptions dep_opts{};
        bool fastprune{false};
        bool enforce_bip94{false};
    };

    struct MainNetOptions {
        DeploymentOptions dep_opts{};
    };

    struct TestNetOptions {
        DeploymentOptions dep_opts{};
    };

    // COMMENT HOUSE: Functions that create the settings for each network.
    static std::unique_ptr<const CChainParams> RegTest(const RegTestOptions& options);
    static std::unique_ptr<const CChainParams> RegTest() { const RegTestOptions opts{}; return RegTest(opts); }
    static std::unique_ptr<const CChainParams> SigNet(const SigNetOptions& options);
    static std::unique_ptr<const CChainParams> SigNet() { const SigNetOptions opts{}; return SigNet(opts); }
    static std::unique_ptr<const CChainParams> Main(const MainNetOptions& options);
    static std::unique_ptr<const CChainParams> Main() { const MainNetOptions opts{}; return Main(opts); }
    static std::unique_ptr<const CChainParams> TestNet(const TestNetOptions& options);
    static std::unique_ptr<const CChainParams> TestNet() { const TestNetOptions opts{}; return TestNet(opts); }
    static std::unique_ptr<const CChainParams> TestNet4(const TestNetOptions& options);
    static std::unique_ptr<const CChainParams> TestNet4() { const TestNetOptions opts{}; return TestNet4(opts); }

protected:
    CChainParams() = default;

    // COMMENT HOUSE: The stored values, filled in for each network by
    // kernel/chainparams.cpp.
    Consensus::Params consensus;
    MessageStartChars pchMessageStart;
    uint16_t nDefaultPort;
    uint64_t nPruneAfterHeight;
    uint64_t m_assumed_blockchain_size;
    uint64_t m_assumed_chain_state_size;
    std::vector<std::string> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::string bech32_hrp;
    std::string silent_payments_hrp;
    ChainType m_chain_type;
    CBlock genesis;
    std::vector<uint8_t> vFixedSeeds;
    bool fDefaultConsistencyChecks;
    bool m_is_mockable_chain;
    std::vector<AssumeutxoData> m_assumeutxo_data;
    ChainTxData chainTxData;
    HeadersSyncParams m_headers_sync_params;

    void ApplyDeploymentOptions(const DeploymentOptions& opts);
};

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& pchMessageStart);

#endif // BITCOIN_KERNEL_CHAINPARAMS_H
