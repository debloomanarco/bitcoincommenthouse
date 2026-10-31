// Copyright (c) 2013-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// The code for a few hashing helpers announced in hash.h (read that first:
// it explains hashing as a "digital fingerprint"). Most of hash.h needs no
// .cpp file. These four do:
//   - MurmurHash3(): a FAST but NOT secure hash, used by bloom filters
//     (common/bloom.cpp).
//   - BIP32Hash():   used by wallets to derive child keys.
//   - SHA256Uint256(): a single SHA-256 of a 32-byte value.
//   - TaggedHash():  the "labelled" hash Taproot uses (Phase 8).
#include <hash.h>
#include <span.h>
#include <crypto/common.h>
#include <crypto/hmac_sha512.h>

#include <bit>
#include <string>

// COMMENT HOUSE: MurmurHash3 mixes the data 4 bytes at a time using
// multiplication, bit rotation (std::rotl) and XOR (^), then "finalises"
// the result so every input bit affects every output bit. It is much faster
// than SHA-256, but someone could deliberately find inputs that collide, so
// it is only used where that does not matter, such as bloom filters. The
// seed lets the same data give different hashes.
unsigned int MurmurHash3(unsigned int nHashSeed, std::span<const unsigned char> vDataToHash)
{
    // The following is MurmurHash3 (x86_32), see https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
    uint32_t h1 = nHashSeed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const int nblocks = vDataToHash.size() / 4;

    //----------
    // body
    const uint8_t* blocks = vDataToHash.data();

    for (int i = 0; i < nblocks; ++i) {
        uint32_t k1 = ReadLE32(blocks + i*4);

        k1 *= c1;
        k1 = std::rotl(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = std::rotl(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    //----------
    // tail
    const uint8_t* tail = vDataToHash.data() + nblocks * 4;

    uint32_t k1 = 0;

    switch (vDataToHash.size() & 3) {
        case 3:
            k1 ^= tail[2] << 16;
            [[fallthrough]];
        case 2:
            k1 ^= tail[1] << 8;
            [[fallthrough]];
        case 1:
            k1 ^= tail[0];
            k1 *= c1;
            k1 = std::rotl(k1, 15);
            k1 *= c2;
            h1 ^= k1;
    }

    //----------
    // finalization
    h1 ^= vDataToHash.size();
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

// COMMENT HOUSE: BIP32Hash(): the step that makes child key number nChild
// from a parent key and its chain code (see Derive() in key.h). HMAC-SHA512
// is a "keyed" hash: a hash mixed with a secret, here the chain code.
void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64])
{
    unsigned char num[4];
    WriteBE32(num, nChild);
    CHMAC_SHA512(chainCode.begin(), chainCode.size()).Write(&header, 1).Write(data, 32).Write(num, 4).Finalize(output);
}

uint256 SHA256Uint256(const uint256& input)
{
    uint256 result;
    CSHA256().Write(input.begin(), 32).Finalize(result.begin());
    return result;
}

// COMMENT HOUSE: TaggedHash() (BIP 340), a hash with a LABEL. It starts by
// hashing the tag text (such as "TapLeaf" or "TapTweak") and feeding that
// hash in twice before any data. Hashes made with different tags can never
// be confused with each other, even for the same data. This stops an
// attacker from reusing a hash made for one purpose in another.
HashWriter TaggedHash(const std::string& tag)
{
    HashWriter writer{};
    uint256 taghash;
    CSHA256().Write((const unsigned char*)tag.data(), tag.size()).Finalize(taghash.begin());
    writer << taghash << taghash;
    return writer;
}
