// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

// COMMENT HOUSE: What is this file?
// It defines the two kinds of transaction ID used everywhere in Bitcoin:
//   - Txid:  the hash of a transaction WITHOUT its witness data. This is the
//            classic "transaction ID" you see in block explorers. Outpoints
//            (COutPoint in primitives/transaction.h) use it to name the coin
//            being spent.
//   - Wtxid: the hash WITH the witness data (BIP 141), used by the
//            witness merkle tree and by peers when announcing transactions
//            (the wtxidrelay notes in net_processing.cpp).
// How they are calculated is in primitives/transaction.cpp.
//
// Both are just 32-byte hashes (uint256, see uint256.h). So why not use
// uint256 for both? Because then it would be easy to pass a Wtxid where a
// Txid was expected by mistake, and the compiler could not tell. Giving them
// different TYPES means such a mix-up is caught when the code is built,
// before it can ever run. It is like having differently shaped plugs so you
// cannot plug a device into the wrong socket.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_PRIMITIVES_TRANSACTION_IDENTIFIER_H
#define BITCOIN_PRIMITIVES_TRANSACTION_IDENTIFIER_H

#include <attributes.h>
#include <uint256.h>

#include <compare>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <variant>

/** transaction_identifier represents the two canonical transaction identifier
 * types (txid, wtxid).*/
// COMMENT HOUSE: transaction_identifier is a "wrapper" around a uint256.
// It is a template with one setting, has_witness. Setting it to false or
// true creates two completely separate types, Txid and Wtxid (see the two
// "using" lines below the class), even though the code is shared.
template <bool has_witness>
class transaction_identifier
{
    uint256 m_wrapped;

    // Note: Use FromUint256 externally instead.
    // COMMENT HOUSE: This constructor is private, so code outside cannot quietly
    // turn any uint256 into an ID. It has to write FromUint256() on purpose,
    // which makes the conversion easy to spot when reading the code.
    transaction_identifier(const uint256& wrapped) : m_wrapped{wrapped} {}

public:
    transaction_identifier() : m_wrapped{} {}
    consteval explicit transaction_identifier(std::string_view hex_str) : m_wrapped{uint256{hex_str}} {}

    constexpr bool operator==(const transaction_identifier&) const = default;
    constexpr auto operator<=>(const transaction_identifier&) const = default;

    // COMMENT HOUSE: ToUint256() and FromUint256() convert to and from a plain
    // uint256 when that is really needed, for example to hash it or store it.
    const uint256& ToUint256() const LIFETIMEBOUND { return m_wrapped; }
    static transaction_identifier FromUint256(const uint256& id) { return {id}; }

    /** Wrapped `uint256` methods. */
    // COMMENT HOUSE: The rest just pass through to uint256: checking for all
    // zeros, reading from and writing to hex text, and turning it into bytes.
    constexpr bool IsNull() const { return m_wrapped.IsNull(); }
    constexpr void SetNull() { m_wrapped.SetNull(); }
    static std::optional<transaction_identifier> FromHex(std::string_view hex)
    {
        auto u{uint256::FromHex(hex)};
        if (!u) return std::nullopt;
        return FromUint256(*u);
    }
    std::string GetHex() const { return m_wrapped.GetHex(); }
    std::string ToString() const { return m_wrapped.ToString(); }
    static constexpr auto size() { return decltype(m_wrapped)::size(); }
    constexpr const std::byte* data() const { return reinterpret_cast<const std::byte*>(m_wrapped.data()); }
    constexpr const std::byte* begin() const { return reinterpret_cast<const std::byte*>(m_wrapped.begin()); }
    constexpr const std::byte* end() const { return reinterpret_cast<const std::byte*>(m_wrapped.end()); }
    template <typename Stream> void Serialize(Stream& s) const { m_wrapped.Serialize(s); }
    template <typename Stream> void Unserialize(Stream& s) { m_wrapped.Unserialize(s); }
};

/** Txid commits to all transaction fields except the witness. */
// COMMENT HOUSE: The two real types: Txid (no witness) and Wtxid (with
// witness).
using Txid = transaction_identifier<false>;
/** Wtxid commits to all transaction fields including the witness. */
using Wtxid = transaction_identifier<true>;

// COMMENT HOUSE: A "concept" is a rule for templates: TxidOrWtxid means "T
// must be either a Txid or a Wtxid".
template <typename T>
concept TxidOrWtxid = std::is_same_v<T, Txid> || std::is_same_v<T, Wtxid>;

// COMMENT HOUSE: GenTxid ("generic txid") holds EITHER a Txid OR a Wtxid, and
// remembers which one. std::variant is a box that holds exactly one of a few
// types. It is used where a peer may announce a transaction by either kind
// of ID. IsWtxid() says which kind it is.
class GenTxid : public std::variant<Txid, Wtxid>
{
public:
    using variant::variant;

    bool IsWtxid() const { return std::holds_alternative<Wtxid>(*this); }

    const uint256& ToUint256() const LIFETIMEBOUND
    {
        return std::visit([](const auto& id) -> const uint256& { return id.ToUint256(); }, *this);
    }

    friend auto operator<=>(const GenTxid& a, const GenTxid& b)
    {
        // Use a reference for read-only access to the hash, avoiding a copy that might not be optimized away.
        return std::tuple<bool, const uint256&>(a.IsWtxid(), a.ToUint256()) <=> std::tuple<bool, const uint256&>(b.IsWtxid(), b.ToUint256());
    }
};

#endif // BITCOIN_PRIMITIVES_TRANSACTION_IDENTIFIER_H
