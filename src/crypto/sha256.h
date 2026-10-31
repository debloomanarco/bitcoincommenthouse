// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This file describes Bitcoin Core's tool for computing SHA-256, the most
// important "hash function" in Bitcoin.
//
// A hash function is like a fingerprint machine for data. You feed in any
// amount of data (one letter, or a whole movie) and get back a short,
// fixed-size result called a "hash". For SHA-256 the result is always 256
// bits, which is 32 bytes. Three properties make it useful:
//   - Same input, same output. Always, on every computer.
//   - Change the input even slightly and the output changes completely and
//     unpredictably.
//   - Nobody knows a practical way to work backwards from a hash to the
//     input, or to find two different inputs with the same hash.
//
// Bitcoin uses SHA-256 everywhere: transaction IDs, block IDs, mining (proof
// of work), and merkle trees. Very often it applies SHA-256 twice in a row,
// which is called "double SHA-256" or "SHA256d".
//
// SHA-256 was not invented by Bitcoin. It is a public standard published by
// the U.S. National Institute of Standards and Technology (NIST) in a document
// called FIPS 180-4, "Secure Hash Standard".
//
// This is a header (.h) file: it lists WHAT the SHA-256 tools are. The actual
// math lives in src/crypto/sha256.cpp, plus files like sha256_sse4.cpp that
// contain faster versions for specific kinds of processors.
//
// The file provides three things:
//   1. CSHA256           - a "hasher" object you feed data into
//   2. SHA256AutoDetect  - picks the fastest version this computer supports
//   3. SHA256D64         - a fast way to compute many double SHA-256 hashes

// COMMENT HOUSE: Header guard. Makes sure this file is only read once,
// even if many other files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_CRYPTO_SHA256_H
#define BITCOIN_CRYPTO_SHA256_H

// COMMENT HOUSE: Standard C++ library files this file needs:
//   - <cstddef>: provides size_t, the type C++ uses for sizes and lengths
//     ("how many bytes?").
//   - <cstdint>: fixed-size whole-number types such as uint32_t (32 bits) and
//     uint64_t (64 bits). The "u" means "unsigned": never negative.
//   - <string>: provides std::string, used for text.
#include <cstddef>
#include <cstdint>
#include <string>

// COMMENT HOUSE: CSHA256.
// A "class" is a bundle of data plus the actions (functions) that work on that
// data. This class is a SHA-256 hasher, used in three steps:
//   1. Create a hasher:                     CSHA256 hasher;
//   2. Feed it data, in any number of
//      pieces:                              hasher.Write(data, len);
//   3. Get the 32-byte result:              hasher.Finalize(result);
//
// Feeding data in pieces is handy: hashing "Hello, " and then "world" gives
// exactly the same hash as hashing "Hello, world" all at once. So the program
// never has to gather all the data in one place before it starts hashing.
/** A hasher class for SHA-256. */
class CSHA256
{
// COMMENT HOUSE: "private" members can only be used by CSHA256's own
// functions; code elsewhere cannot touch them. They hold the hasher's work in
// progress.
private:
    // COMMENT HOUSE: s is the "state": eight 32-bit numbers
    // (8 x 32 = 256 bits). SHA-256 works by repeatedly mixing data into these
    // eight numbers, and when it is finished they become the hash. They start
    // at fixed values chosen by the standard; see Initialize() in
    // src/crypto/sha256.cpp.
    uint32_t s[8];
    // COMMENT HOUSE: buf is a 64-byte waiting area. SHA-256 can only
    // mix in data 64 bytes (one "chunk") at a time. If Write() is given an
    // amount that is not a multiple of 64, the leftover bytes wait here until
    // more data arrives to complete the chunk.
    unsigned char buf[64];
    // COMMENT HOUSE: bytes counts the total number of bytes written so
    // far; "{0}" means it starts at zero. SHA-256 needs this count at the end,
    // because the input's length is mixed into the final hash.
    uint64_t bytes{0};

// COMMENT HOUSE: "public" members can be used by any code.
public:
    // COMMENT HOUSE: The size of a SHA-256 hash: 32 bytes (256 bits).
    static constexpr size_t OUTPUT_SIZE{32};

    // COMMENT HOUSE: The "constructor". It runs automatically when a
    // new CSHA256 is created, and sets the state s to its starting values.
    CSHA256();
    // COMMENT HOUSE: Write feeds len bytes, starting at data, into the
    // hasher. Full 64-byte chunks are mixed into the state right away; any
    // leftover goes into buf. It returns the hasher itself ("CSHA256&"), so
    // calls can be chained: hasher.Write(a, 10).Write(b, 20);
    CSHA256& Write(const unsigned char* data, size_t len);
    // COMMENT HOUSE: Finalize finishes the hash and copies the 32-byte
    // result into hash. To finish, SHA-256 adds "padding" as the standard
    // requires: a single 1 bit, then 0 bits, then the input's total length in
    // bits, so the data fills a whole number of 64-byte chunks.
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    // COMMENT HOUSE: Reset wipes the hasher back to its starting
    // condition so it can be reused for a brand-new hash.
    CSHA256& Reset();
};

// COMMENT HOUSE: Choices of SHA-256 "implementation".
// An implementation is one particular way of writing the SHA-256 code. They
// all give exactly the same answers; some are just much faster on certain
// processors:
//   - STANDARD:  plain C++. Works on any computer.
//   - USE_SSE4:  uses SSE4, extra instructions found on many Intel and AMD
//                processors.
//   - USE_AVX2:  uses AVX2, which can work on several hashes side by side.
//   - USE_SHANI: uses SHA-NI, instructions built into some processors just
//                for computing SHA-256.
//
// How the numbers work: each option is one "flag" bit. "1 << n" means "1
// shifted left n places", a number with only bit n switched on:
//   1 << 0 = binary 001 = 1
//   1 << 1 = binary 010 = 2
//   1 << 2 = binary 100 = 4
// "|" (bitwise OR) combines flags by switching on every bit that is on in
// either side. So USE_ALL = 001 | 010 | 100 = 111 = 7: "all three allowed".
//
// A "namespace" is a labelled box for names. Writing
// sha256_implementation::USE_ALL makes it clear where the name comes from,
// and stops it clashing with other names in the program.
namespace sha256_implementation {
enum UseImplementation : uint8_t {
    STANDARD = 0,
    USE_SSE4 = 1 << 0,
    USE_AVX2 = 1 << 1,
    USE_SHANI = 1 << 2,
    USE_SSE4_AND_AVX2 = USE_SSE4 | USE_AVX2,
    USE_SSE4_AND_SHANI = USE_SSE4 | USE_SHANI,
    USE_ALL = USE_SSE4 | USE_AVX2 | USE_SHANI,
};
}

// COMMENT HOUSE: SHA256AutoDetect.
// Checks which special instructions this computer's processor has, and
// switches the program to the fastest SHA-256 implementation that is both
// available and allowed by use_implementation. With no argument, the default
// USE_ALL allows every option.
//
// Bitcoin Core calls this once at startup (see src/kernel/context.cpp) and
// writes the chosen name to its log, as a line like "Using the 'standard'
// SHA256 implementation" (the name depends on your processor). The benchmarks
// in src/bench/crypto_hash.cpp pass fewer flags so they can compare the speed
// of each implementation.
/** Autodetect the best available SHA256 implementation.
 *  Returns the name of the implementation.
 */
std::string SHA256AutoDetect(sha256_implementation::UseImplementation use_implementation = sha256_implementation::USE_ALL);

// COMMENT HOUSE: SHA256D64.
// "D" means double SHA-256 (SHA-256 applied twice), and "64" means every input
// is exactly 64 bytes long. Give it `blocks` inputs of 64 bytes each, lined up
// one after another, and it produces `blocks` results of 32 bytes each.
// ("blocks" here just means "pieces of data", not Bitcoin blocks.)
//
// Why such a specific job? It is exactly what building a merkle tree needs.
// A merkle tree combines many transaction hashes into one: at each step, two
// 32-byte hashes are joined into one 64-byte input and double-hashed.
// ComputeMerkleRoot() in src/consensus/merkle.cpp calls this function to hash
// a whole level of the tree in one go. Being this specialized lets the code
// compute 2, 4, or 8 hashes side by side when the processor supports it.
//
// "unsigned char*" is a "pointer": the memory address where a list of bytes
// begins. The caller must make sure the input and output areas are big
// enough, as the original comment below describes.
/** Compute multiple double-SHA256's of 64-byte blobs.
 *  output:  pointer to a blocks*32 byte output buffer
 *  input:   pointer to a blocks*64 byte input buffer
 *  blocks:  the number of hashes to compute.
 */
void SHA256D64(unsigned char* output, const unsigned char* input, size_t blocks);

// COMMENT HOUSE: End of the header guard that started near the top.
#endif // BITCOIN_CRYPTO_SHA256_H
