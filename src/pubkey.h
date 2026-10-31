// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This file describes PUBLIC keys, the shareable half of a key pair (see
// key.h for private keys and the big picture). A public key is a point on
// the secp256k1 curve: a pair of very large numbers, x and y. Its main job is
// to VERIFY signatures: to check that a signature was made by the matching
// private key, without ever knowing that private key.
//
// The main pieces:
//   - CKeyID:      a short (20-byte) fingerprint of a public key, used in
//                  classic Bitcoin addresses.
//   - CPubKey:     a public key, used for ECDSA signatures.
//   - XOnlyPubKey: the 32-byte public key form used by Taproot (Phase 8).
// The rest (EllSwiftPubKey, CExtPubKey) is for encrypted connections and
// wallets. You can skip it.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_PUBKEY_H
#define BITCOIN_PUBKEY_H

#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cassert>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

inline constexpr unsigned int BIP32_EXTKEY_SIZE = 74;
inline constexpr unsigned int BIP32_EXTKEY_WITH_VERSION_SIZE = 78;

using KeyFingerprint = std::array<unsigned char, 4>;

/** A reference to a CKey: the Hash160 of its serialized public key */
// COMMENT HOUSE: CKeyID, the Hash160 of a public key (SHA-256 then
// RIPEMD-160, see hash.h), which is 20 bytes. A classic address beginning
// with "1" is basically this fingerprint written in a friendly form. Locking
// coins to the hash, instead of the key itself, makes addresses shorter. It
// also keeps the actual public key hidden until the coins are spent.
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    explicit CKeyID(const uint160& in) : uint160(in) {}
    KeyFingerprint fingerprint() const
    {
        KeyFingerprint ret;
        std::copy_n(begin(), ret.size(), ret.begin());
        return ret;
    }
};

/** An encapsulated public key. */
// COMMENT HOUSE: CPubKey, a public key, stored in one of two forms:
//   - uncompressed, 65 bytes: the byte 0x04, then x (32 bytes), then
//     y (32 bytes).
//   - compressed, 33 bytes: the byte 0x02 or 0x03, then only x. For any x
//     there are just two possible y values on the curve, one even and one
//     odd. So 02 means "the even one" and 03 means "the odd one", and y can
//     be worked out again when needed.
// Almost all keys today are compressed. A DER signature (see key.cpp) is up
// to 72 bytes (SIGNATURE_SIZE).
class CPubKey
{
public:
    /**
     * secp256k1:
     */
    static constexpr unsigned int SIZE                   = 65;
    static constexpr unsigned int COMPRESSED_SIZE        = 33;
    static constexpr unsigned int SIGNATURE_SIZE         = 72;
    static constexpr unsigned int COMPACT_SIGNATURE_SIZE = 65;
    /**
     * see www.keylength.com
     * script supports up to 75 for single byte push
     */
    static_assert(
        SIZE >= COMPRESSED_SIZE,
        "COMPRESSED_SIZE is larger than SIZE");

private:

    /**
     * Just store the serialized data.
     * Its length can very cheaply be computed from the first byte.
     */
    unsigned char vch[SIZE];

    //! Compute the length of a pubkey with a given first byte.
    // COMMENT HOUSE: The first byte tells you the length: 02 or 03 means
    // compressed (33 bytes), and 04 means uncompressed (65 bytes). 06 and 07 are
    // an old, unusual "hybrid" form.
    unsigned int static GetLen(unsigned char chHeader)
    {
        if (chHeader == 2 || chHeader == 3)
            return COMPRESSED_SIZE;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return SIZE;
        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate()
    {
        vch[0] = 0xFF;
    }

public:

    bool static ValidSize(const std::vector<unsigned char> &vch) {
      return vch.size() > 0 && GetLen(vch[0]) == vch.size();
    }

    //! Construct an invalid public key.
    CPubKey()
    {
        Invalidate();
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend - pbegin))
            memcpy(vch, (unsigned char*)&pbegin[0], len);
        else
            Invalidate();
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    explicit CPubKey(std::span<const uint8_t> _vch)
    {
        Set(_vch.begin(), _vch.end());
    }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return GetLen(vch[0]); }
    const unsigned char* data() const { return vch; }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] == b.vch[0] &&
               memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator<(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] < b.vch[0] ||
               (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }
    friend bool operator>(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] > b.vch[0] ||
               (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) > 0);
    }

    //! Implement serialization, as if this was a byte vector.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s << std::span{vch, len};
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const unsigned int len(::ReadCompactSize(s));
        if (len <= SIZE) {
            s >> std::span{vch, len};
            if (len != size()) {
                Invalidate();
            }
        } else {
            // invalid pubkey, skip available data
            s.ignore(len);
            Invalidate();
        }
    }

    //! Get the KeyID of this public key (hash of its serialization)
    // COMMENT HOUSE: GetID() gives this key's 20-byte fingerprint (Hash160).
    CKeyID GetID() const
    {
        return CKeyID(Hash160(std::span{vch}.first(size())));
    }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const
    {
        return Hash(std::span{vch}.first(size()));
    }

    /*
     * Check syntactic correctness.
     *
     * When setting a pubkey (Set()) or deserializing fails (its header bytes
     * don't match the length of the data), the size is set to 0. Thus,
     * by checking size, one can observe whether Set() or deserialization has
     * failed.
     *
     * This does not check for more than that. In particular, it does not verify
     * that the coordinates correspond to a point on the curve (see IsFullyValid()
     * for that instead).
     *
     * Note that this is consensus critical as CheckECDSASignature() calls it!
     */
    // COMMENT HOUSE: IsValid() only checks that the key has a sensible length. It
    // does NOT check that the point is actually on the curve. IsFullyValid() does
    // that, but it is slower.
    bool IsValid() const
    {
        return size() > 0;
    }

    /** Check if a public key is a syntactically valid compressed or uncompressed key. */
    bool IsValidNonHybrid() const noexcept
    {
        return size() > 0 && (vch[0] == 0x02 || vch[0] == 0x03 || vch[0] == 0x04);
    }

    //! fully validate whether this is a valid public key (more expensive than IsValid())
    bool IsFullyValid() const;

    //! Check whether this is a compressed public key.
    bool IsCompressed() const
    {
        return size() == COMPRESSED_SIZE;
    }

    /**
     * Verify a DER signature (~72 bytes).
     * If this public key is not fully valid, the return value will be false.
     */
    // COMMENT HOUSE: Verify(), the most important function here: does vchSig
    // prove that the owner of the matching private key signed this hash? It
    // returns true or false. The code is in pubkey.cpp.
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const;

    /**
     * Check whether a signature is normalized (lower-S).
     */
    // COMMENT HOUSE: For every valid signature there is a "twin" with a different
    // S value (see SigHasLowR() in key.cpp) that is also valid. That would let
    // someone change a transaction's bytes, and so its txid, without the owner's
    // permission. To prevent that, policy only accepts the "low S" twin.
    static bool CheckLowS(const std::vector<unsigned char>& vchSig);

    //! Recover a public key from a compact signature.
    bool RecoverCompact(const uint256& hash, const std::vector<unsigned char>& vchSig);

    //! Turn this public key into an uncompressed public key.
    bool Decompress();

    //! Derive BIP32 child pubkey.
    [[nodiscard]] bool Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc, uint256* bip32_tweak_out = nullptr) const;
};

// COMMENT HOUSE: XOnlyPubKey, a 32-byte public key that stores ONLY x.
// Taproot (BIP 340/341) always picks the version of a point with an even y,
// so even the 02/03 byte is unnecessary. These keys verify Schnorr
// signatures, and can be "tweaked" to hide a tree of spending scripts inside
// them. All of this is explained in Phase 8.
class XOnlyPubKey
{
private:
    uint256 m_keydata;

public:
    /** Nothing Up My Sleeve point H
     *  Used as an internal key for provably disabling the key path spend
     *  see BIP341 for more details */
    static const XOnlyPubKey NUMS_H;

    /** Construct an empty x-only pubkey. */
    XOnlyPubKey() = default;

    XOnlyPubKey(const XOnlyPubKey&) = default;
    XOnlyPubKey& operator=(const XOnlyPubKey&) = default;

    /** Determine if this pubkey is fully valid. This is true for approximately 50% of all
     *  possible 32-byte arrays. If false, VerifySchnorr, CheckTapTweak and CreateTapTweak
     *  will always fail. */
    bool IsFullyValid() const;

    /** Test whether this is the 0 key (the result of default construction). This implies
     *  !IsFullyValid(). */
    bool IsNull() const { return m_keydata.IsNull(); }

    /** Construct an x-only pubkey from exactly 32 bytes. */
    constexpr explicit XOnlyPubKey(std::span<const unsigned char> bytes) : m_keydata{bytes} {}

    /** Construct an x-only pubkey from a normal pubkey. */
    explicit XOnlyPubKey(const CPubKey& pubkey) : XOnlyPubKey(std::span{pubkey}.subspan(1, 32)) {}

    /** Verify a Schnorr signature against this public key.
     *
     * sigbytes must be exactly 64 bytes.
     */
    // COMMENT HOUSE: Checks a 64-byte Schnorr signature. Same idea as
    // CPubKey::Verify(), but for the newer signature type.
    bool VerifySchnorr(const uint256& msg, std::span<const unsigned char> sigbytes) const;

    /** Compute the Taproot tweak as specified in BIP341, with *this as internal
     * key:
     *  - if merkle_root == nullptr: H_TapTweak(xonly_pubkey)
     *  - otherwise:                 H_TapTweak(xonly_pubkey || *merkle_root)
     *
     * Note that the behavior of this function with merkle_root != nullptr is
     * consensus critical.
     */
    // COMMENT HOUSE: The Taproot "tweak" functions. Phase 8 explains them.
    uint256 ComputeTapTweakHash(const uint256* merkle_root) const;

    /** Verify that this is a Taproot tweaked output point, against a specified internal key,
     *  Merkle root, and parity. */
    bool CheckTapTweak(const XOnlyPubKey& internal, const uint256& merkle_root, bool parity) const;

    /** Construct a Taproot tweaked output point with this point as internal key. */
    std::optional<std::pair<XOnlyPubKey, bool>> CreateTapTweak(const uint256* merkle_root) const;

    /** Returns a list of CKeyIDs for the CPubKeys that could have been used to create this XOnlyPubKey.
     * As the CKeyID is the Hash160(full pubkey), the produced CKeyIDs are for the versions of this
     * XOnlyPubKey with 0x02 and 0x03 prefixes.
     * This is needed for key lookups since keys are indexed by CKeyID.
     */
    std::vector<CKeyID> GetKeyIDs() const;
    /** Returns this XOnlyPubKey with 0x02 and 0x03 prefixes */
    std::vector<CPubKey> GetCPubKeys() const;

    CPubKey GetEvenCorrespondingCPubKey() const;

    const unsigned char& operator[](int pos) const { return *(m_keydata.begin() + pos); }
    static constexpr size_t size() { return decltype(m_keydata)::size(); }
    const unsigned char* data() const { return m_keydata.begin(); }
    const unsigned char* begin() const { return m_keydata.begin(); }
    const unsigned char* end() const { return m_keydata.end(); }
    unsigned char* data() { return m_keydata.begin(); }
    unsigned char* begin() { return m_keydata.begin(); }
    unsigned char* end() { return m_keydata.end(); }
    bool operator==(const XOnlyPubKey& other) const { return m_keydata == other.m_keydata; }
    bool operator<(const XOnlyPubKey& other) const { return m_keydata < other.m_keydata; }

    //! Implement serialization without length prefixes since it is a fixed length
    SERIALIZE_METHODS(XOnlyPubKey, obj) { READWRITE(obj.m_keydata); }
};

/** An ElligatorSwift-encoded public key. */
struct EllSwiftPubKey
{
private:
    static constexpr size_t SIZE = 64;
    std::array<std::byte, SIZE> m_pubkey;

public:
    /** Default constructor creates all-zero pubkey (which is valid). */
    EllSwiftPubKey() noexcept = default;

    /** Construct a new ellswift public key from a given serialization. */
    EllSwiftPubKey(std::span<const std::byte> ellswift) noexcept;

    /** Decode to normal compressed CPubKey (for debugging purposes). */
    CPubKey Decode() const;

    // Read-only access for serialization.
    const std::byte* data() const { return m_pubkey.data(); }
    static constexpr size_t size() { return SIZE; }
    auto begin() const { return m_pubkey.cbegin(); }
    auto end() const { return m_pubkey.cend(); }

    bool friend operator==(const EllSwiftPubKey& a, const EllSwiftPubKey& b)
    {
        return a.m_pubkey == b.m_pubkey;
    }
};

// COMMENT HOUSE: CExtPubKey, an extended public key (BIP 32) used by wallets
// to create child public keys. You can skip it.
struct CExtPubKey {
    unsigned char version[4];
    unsigned char nDepth;
    KeyFingerprint fingerprint;
    unsigned int nChild;
    ChainCode chaincode;
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b)
    {
        return a.nDepth == b.nDepth &&
            a.fingerprint == b.fingerprint &&
            a.nChild == b.nChild &&
            a.chaincode == b.chaincode &&
            a.pubkey == b.pubkey;
    }

    friend bool operator<(const CExtPubKey &a, const CExtPubKey &b)
    {
        if (a.pubkey < b.pubkey) {
            return true;
        } else if (a.pubkey > b.pubkey) {
            return false;
        }
        return a.chaincode < b.chaincode;
    }

    KeyFingerprint id_key_fingerprint() const
    {
        return pubkey.GetID().fingerprint();
    }

    //! BIP32 serialization without the version bytes (BIP32_EXTKEY_SIZE bytes)
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        assert(pubkey.size() == CPubKey::COMPRESSED_SIZE);
        s << nDepth << fingerprint << Using<BigEndianFormatter<4>>(nChild) << chaincode << std::span{pubkey.data(), CPubKey::COMPRESSED_SIZE};
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        std::array<unsigned char, CPubKey::COMPRESSED_SIZE> ser_pubkey;
        s >> nDepth >> fingerprint >> Using<BigEndianFormatter<4>>(nChild) >> chaincode >> ser_pubkey;
        pubkey.Set(ser_pubkey.begin(), ser_pubkey.end());
        if ((nDepth == 0 && (nChild != 0 || fingerprint != KeyFingerprint{})) || !pubkey.IsFullyValid()) pubkey = CPubKey();
    }
    [[nodiscard]] bool Derive(CExtPubKey& out, unsigned int nChild, uint256* bip32_tweak_out = nullptr) const;
};

#endif // BITCOIN_PUBKEY_H
