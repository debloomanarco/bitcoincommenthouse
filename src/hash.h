// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// src/crypto/sha256.h gives Bitcoin Core a basic SHA-256 tool. This file
// builds the specific "recipes" Bitcoin actually uses on top of it:
//   - Double SHA-256 (CHash256, Hash, HashWriter): SHA-256 applied twice.
//     This is how transaction IDs and block hashes are made.
//   - Hash160 (CHash160): SHA-256 followed by RIPEMD-160, giving a shorter
//     20-byte result. Used for some kinds of Bitcoin addresses.
//   - Tagged hashes (TaggedHash): SHA-256 with a "label" mixed in, used by
//     Taproot.
//   - A few special-purpose helpers, explained where they appear below.
//
// A hash is a fixed-size "fingerprint" of data; see the explanation at the top
// of src/crypto/sha256.h if that idea is new to you. The hash results are
// stored in uint256 (32 bytes) or uint160 (20 bytes), from src/uint256.h.

// COMMENT HOUSE: Header guard. Makes sure this file is only read once,
// even if many other files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

// COMMENT HOUSE: Other files this one needs, including the two basic
// hash functions it builds on (crypto/sha256.h and crypto/ripemd160.h) and
// serialize.h, which turns objects into bytes so they can be hashed.
#include <attributes.h>
#include <crypto/common.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <prevector.h>
#include <serialize.h>
#include <span.h>
#include <support/cleanse.h>
#include <uint256.h>

#include <string>
#include <vector>

// COMMENT HOUSE: ChainCode.
// BIP32 (Bitcoin Improvement Proposal 32) describes "HD wallets": wallets
// that can create a whole family of keys from one starting secret. Besides
// each key, BIP32 uses an extra 32 bytes of secret data called a "chain code"
// to work out the next keys in the family.
//
// ChainCode is a 32-byte blob (built on base_blob<256> from uint256.h) with one
// extra safety feature: "~ChainCode()" is its "destructor", code that runs
// automatically when the object is thrown away. It calls memory_cleanse() to
// overwrite the secret bytes with zeros, so they do not linger in the
// computer's memory where something else might find them.
/** A BIP32 chain code. Cleansed on destruction. */
class ChainCode : public base_blob<256> {
public:
    constexpr ChainCode() = default;
    constexpr explicit ChainCode(std::span<const unsigned char> vch) : base_blob<256>(vch) {}
    constexpr explicit ChainCode(const base_blob<256>& b) : base_blob<256>(b) {}
    ~ChainCode() { memory_cleanse(data(), size()); }
};

// COMMENT HOUSE: CHash256, the double SHA-256 hasher.
// Used just like CSHA256 (Write the data in, then Finalize), but Finalize does
// two rounds:
//   1. Finish the normal SHA-256 hash of the data into buf.
//   2. Reset, then hash those 32 bytes of buf AGAIN with SHA-256.
// The second result is the answer: SHA-256(SHA-256(data)).
//
// "std::span" is a view of a list of bytes: where it starts and how long it
// is. The assert stops the program if the output space is not exactly 32
// bytes, which would be a programming mistake.
/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256 {
private:
    CSHA256 sha;
public:
    static constexpr size_t OUTPUT_SIZE{CSHA256::OUTPUT_SIZE};

    void Finalize(std::span<unsigned char> output) {
        assert(output.size() == OUTPUT_SIZE);
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(output.data());
    }

    CHash256& Write(std::span<const unsigned char> input) {
        sha.Write(input.data(), input.size());
        return *this;
    }

    CHash256& Reset() {
        sha.Reset();
        return *this;
    }
};

// COMMENT HOUSE: CHash160, the "Hash160" hasher.
// Same idea, but the second round uses a different hash function,
// RIPEMD-160, which produces 20 bytes instead of 32:
//   Hash160(data) = RIPEMD-160(SHA-256(data))
// The shorter result makes addresses shorter. For example, the "key ID" of a
// public key is the Hash160 of that key (see GetID() in src/pubkey.h), and
// that is what classic Bitcoin addresses starting with "1" are built from.
/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
class CHash160 {
private:
    CSHA256 sha;
public:
    static constexpr size_t OUTPUT_SIZE{CRIPEMD160::OUTPUT_SIZE};

    void Finalize(std::span<unsigned char> output) {
        assert(output.size() == OUTPUT_SIZE);
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        CRIPEMD160().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(output.data());
    }

    CHash160& Write(std::span<const unsigned char> input) {
        sha.Write(input.data(), input.size());
        return *this;
    }

    CHash160& Reset() {
        sha.Reset();
        return *this;
    }
};

// COMMENT HOUSE: Hash(...) shortcuts.
// One-line ways to get a double SHA-256 hash without creating a hasher
// yourself. The first version hashes one thing; the second hashes two things
// joined end to end ("concatenated"). MakeUCharSpan turns the input into a
// view of its raw bytes.
//
// "template<typename T>" means these work with many different input types: T
// is filled in with whatever type you pass.
/** Compute the 256-bit hash of an object. */
template<typename T>
inline uint256 Hash(const T& in1)
{
    uint256 result;
    CHash256().Write(MakeUCharSpan(in1)).Finalize(result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of two objects. */
template<typename T1, typename T2>
inline uint256 Hash(const T1& in1, const T2& in2) {
    uint256 result;
    CHash256().Write(MakeUCharSpan(in1)).Write(MakeUCharSpan(in2)).Finalize(result);
    return result;
}

// COMMENT HOUSE: The same kind of shortcut for Hash160. For example,
// src/addresstype.cpp uses it to make the 20-byte hash of a script for
// "pay-to-script-hash" (P2SH) addresses.
/** Compute the 160-bit hash an object. */
template<typename T1>
inline uint160 Hash160(const T1& in1)
{
    uint160 result;
    CHash160().Write(MakeUCharSpan(in1)).Finalize(result);
    return result;
}

// COMMENT HOUSE: HashWriter.
// This is the most-used hasher in Bitcoin Core. Instead of handing it raw
// bytes, you hand it whole objects with "<<", like this:
//   (HashWriter{} << block_header).GetHash()
// Each object is "serialized" (turned into the exact bytes Bitcoin uses to
// save it or send it over the network), and those bytes go straight into
// SHA-256. That is exactly how a block's hash is computed (see
// CBlockHeader::GetHash() in src/primitives/block.cpp) and how a transaction
// ID is computed (in src/primitives/transaction.cpp).
//
// Ways to get the result:
//   - GetHash():      double SHA-256 (the usual Bitcoin hash).
//   - GetSHA256():    single SHA-256 (used for tagged hashes, see below).
//   - GetCheapHash(): just the first 8 bytes of GetHash(), as one number.
//                     Handy when you only need a random-looking number, not
//                     a secure fingerprint; src/addrman.cpp uses it to sort
//                     peer addresses into "buckets".
// "Invalidates this object" means: once you have taken the result, do not
// keep using the same HashWriter. Start a new one.
/** A writer stream (for serialization) that computes a 256-bit hash. */
class HashWriter
{
private:
    CSHA256 ctx;

public:
    void write(std::span<const std::byte> src)
    {
        ctx.Write(UCharCast(src.data()), src.size());
    }

    /** Compute the double-SHA256 hash of all data written to this object.
     *
     * Invalidates this object.
     */
    uint256 GetHash() {
        uint256 result;
        ctx.Finalize(result.begin());
        ctx.Reset().Write(result.begin(), CSHA256::OUTPUT_SIZE).Finalize(result.begin());
        return result;
    }

    /** Compute the SHA256 hash of all data written to this object.
     *
     * Invalidates this object.
     */
    uint256 GetSHA256() {
        uint256 result;
        ctx.Finalize(result.begin());
        return result;
    }

    /**
     * Returns the first 64 bits from the resulting hash.
     */
    inline uint64_t GetCheapHash() {
        uint256 result = GetHash();
        return ReadLE64(result.begin());
    }

    template <typename T>
    HashWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }
};

// COMMENT HOUSE: HashVerifier and HashedSourceWriter.
// These are used to detect damaged files. The idea is a "checksum": when
// saving a file, also save a hash of its contents. When loading it later,
// hash what you read and compare. If even one byte was damaged, the hashes
// will not match.
//
//   - HashedSourceWriter writes data to a file (the "source") AND hashes it
//     at the same time.
//   - HashVerifier reads data from a file AND hashes what it read, so the
//     result can be compared with the saved hash. ignore() skips bytes, but
//     still hashes them, 1024 bytes at a time.
//
// Both are built on HashWriter (": public HashWriter"), so they reuse its
// hashing code. src/addrdb.cpp uses this pair to save and check peers.dat, the
// file of known network addresses, and src/node/blockstorage.cpp uses
// HashVerifier when reading block "undo" data.
//
// LIFETIMEBOUND is a hint for the compiler: these objects keep a reference to
// the source, so the source must stay alive at least as long as they do.
/** Reads data from an underlying stream, while hashing the read data. */
template <typename Source>
class HashVerifier : public HashWriter
{
private:
    Source& m_source;

public:
    explicit HashVerifier(Source& source LIFETIMEBOUND) : m_source{source} {}

    void read(std::span<std::byte> dst)
    {
        m_source.read(dst);
        this->write(dst);
    }

    void ignore(size_t num_bytes)
    {
        std::byte data[1024];
        while (num_bytes > 0) {
            size_t now = std::min<size_t>(num_bytes, 1024);
            read({data, now});
            num_bytes -= now;
        }
    }

    template <typename T>
    HashVerifier<Source>& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }
};

/** Writes data to an underlying source stream, while hashing the written data. */
template <typename Source>
class HashedSourceWriter : public HashWriter
{
private:
    Source& m_source;

public:
    explicit HashedSourceWriter(Source& source LIFETIMEBOUND) : HashWriter{}, m_source{source} {}

    void write(std::span<const std::byte> src)
    {
        m_source.write(src);
        HashWriter::write(src);
    }

    template <typename T>
    HashedSourceWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }
};

// COMMENT HOUSE: SHA256Uint256 computes a SINGLE SHA-256 of a 32-byte
// value. It is used in src/script/interpreter.cpp while preparing the data
// that gets signed in a transaction. "[[nodiscard]]" makes the compiler warn
// if someone calls the function and ignores its result, which would almost
// certainly be a mistake.
/** Single-SHA256 a 32-byte input (represented as uint256). */
[[nodiscard]] uint256 SHA256Uint256(const uint256& input);

// COMMENT HOUSE: MurmurHash3 is a fast hash function that is NOT
// meant to be secure. It is used by "bloom filters" (src/common/bloom.cpp), a
// compact way of testing "is this item probably in the set?". nHashSeed is a
// starting number that changes the output, so one function can act like many
// different hash functions.
unsigned int MurmurHash3(unsigned int nHashSeed, std::span<const unsigned char> vDataToHash);

// COMMENT HOUSE: BIP32Hash is the step that BIP32 HD wallets use to
// get from one key to the next ("child number" nChild). It uses HMAC-SHA512,
// a keyed hash that mixes the chain code (see ChainCode above) together with
// the key data and the child number, producing 64 bytes (see
// src/hash.cpp).
void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]);

// COMMENT HOUSE: Tagged hashes (from BIP 340, used by Taproot).
// A tagged hash mixes a label, such as "TapLeaf", into the hash:
//   TaggedHash(tag, message) = SHA-256(SHA-256(tag) + SHA-256(tag) + message)
// where "+" means "joined end to end". Hashes made for different purposes
// get different labels, so a hash made for one purpose can never be mistaken
// for, or reused as, a hash made for another.
//
// This function returns a HashWriter that already has SHA-256(tag) written
// into it twice. You then write the message and call GetSHA256() (single
// SHA-256, not GetHash()). src/script/interpreter.cpp creates them once for
// the labels "TapSighash", "TapLeaf" and "TapBranch".
/** Return a HashWriter primed for tagged hashes (as specified in BIP 340).
 *
 * The returned object will have SHA256(tag) written to it twice (= 64 bytes).
 * A tagged hash can be computed by feeding the message into this object, and
 * then calling HashWriter::GetSHA256().
 */
HashWriter TaggedHash(const std::string& tag);

// COMMENT HOUSE: A shortcut for a plain RIPEMD-160 hash (20 bytes),
// without the SHA-256 step that Hash160 adds first.
/** Compute the 160-bit RIPEMD-160 hash of an array. */
inline uint160 RIPEMD160(std::span<const unsigned char> data)
{
    uint160 result;
    CRIPEMD160().Write(data.data(), data.size()).Finalize(result.begin());
    return result;
}

// COMMENT HOUSE: End of the header guard that started near the top.
#endif // BITCOIN_HASH_H
