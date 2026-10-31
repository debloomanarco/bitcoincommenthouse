// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// This file defines uint256 and uint160: containers that hold exactly 256 bits
// (32 bytes) or 160 bits (20 bytes) of data.
//
// You will see uint256 almost everywhere in Bitcoin Core, because a SHA-256
// hash is exactly 256 bits. Transaction IDs, block hashes and merkle roots are
// all stored in uint256s. For example, in src/primitives/block.h every block
// header stores the hash of the block before it as "uint256 hashPrevBlock".
// uint160 is used for 160-bit hashes, such as the result of Hash160() in
// src/hash.h, which is used in some kinds of Bitcoin addresses.
//
// An important detail, also stated in the original comments below: despite
// the "uint" (unsigned integer) in the name, these are NOT numbers you can do
// math with. They are "opaque blobs": fixed-size bags of bytes that you can
// store, copy, compare and print, but not add or multiply. When Bitcoin Core
// needs to treat a hash as a number (for example in mining, to check that a
// block hash is below the target), it converts it to arith_uint256, defined in
// src/arith_uint256.h.

// COMMENT HOUSE: Header guard. Makes sure this file is only read once,
// even if many other files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

// COMMENT HOUSE: Other files this one needs. Files in <...> without a
// folder name (like <array>) come from the standard C++ library. The others
// are Bitcoin Core's own helpers, for example for reading bytes and for
// converting between bytes and hexadecimal ("hex") text.
#include <crypto/common.h>
#include <crypto/hex_base.h>
#include <span.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <compare>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

// COMMENT HOUSE: base_blob, the shared blueprint.
// "template<unsigned int BITS>" makes this a template: a blueprint with a
// blank to fill in. base_blob<256> is a 256-bit blob and base_blob<160> is a
// 160-bit blob. Writing the code once as a template means uint256 and uint160
// share all of it instead of repeating it.
/** Template base class for fixed-sized opaque blobs. */
template<unsigned int BITS>
class base_blob
{
// COMMENT HOUSE: "protected" members can be used by this class and by
// classes built on top of it (uint256 and uint160 below), but not by other
// code.
protected:
    // COMMENT HOUSE: WIDTH is the size in bytes. There are 8 bits in a
    // byte, so 256 bits / 8 = 32 bytes, and 160 bits / 8 = 20 bytes.
    static constexpr int WIDTH = BITS / 8;
    // COMMENT HOUSE: static_assert is a check done while the program is
    // being built. If someone tried to make a blob whose size is not a whole
    // number of bytes (BITS % 8 means "the remainder after dividing by 8"),
    // the build would stop with this error message.
    static_assert(BITS % 8 == 0, "base_blob currently only supports whole bytes.");
    // COMMENT HOUSE: m_data is where the bytes actually live: a
    // fixed-size array of WIDTH bytes. (uint8_t is an 8-bit number, 0 to 255,
    // which is one byte.) The "m_" at the start is a naming habit in Bitcoin
    // Core meaning "member": a piece of data belonging to the object.
    std::array<uint8_t, WIDTH> m_data;
    static_assert(WIDTH == sizeof(m_data), "Sanity check");

public:
    // COMMENT HOUSE: Constructors: the ways to create a blob.
    //   - base_blob()            all bytes set to 0.
    //   - base_blob(uint8_t v)   first byte set to v, the rest 0. Used for
    //                            small constants such as uint256::ONE below.
    //   - base_blob(vch)         copies bytes from vch, which must be exactly
    //                            WIDTH bytes long. "assert" stops the program
    //                            if that is not true, because it would be a
    //                            programming mistake.
    // "explicit" means the conversion must be written out on purpose; C++ will
    // not silently turn, say, a number into a uint256 behind your back.
    /* construct 0 value by default */
    constexpr base_blob() : m_data() {}

    /* constructor for constants between 1 and 255 */
    constexpr explicit base_blob(uint8_t v) : m_data{v} {}

    constexpr explicit base_blob(std::span<const unsigned char> vch)
    {
        assert(vch.size() == WIDTH);
        std::copy(vch.begin(), vch.end(), m_data.begin());
    }

    // COMMENT HOUSE: Creates a blob from hex text written directly in
    // the code. "consteval" means this MUST be worked out while the program is
    // being built, so a typo in the hex text becomes a build error instead of
    // a bug at run time. Its code is further down, after this class.
    consteval explicit base_blob(std::string_view hex_str);

    // COMMENT HOUSE: IsNull() answers "is every byte zero?". An
    // all-zero hash is often used to mean "nothing here yet". The [](...) part
    // is a "lambda": a tiny unnamed function, here asking "is this byte 0?",
    // that std::all_of checks against every byte.
    constexpr bool IsNull() const
    {
        return std::all_of(m_data.begin(), m_data.end(), [](uint8_t val) {
            return val == 0;
        });
    }

    // COMMENT HOUSE: SetNull() sets every byte back to zero.
    constexpr void SetNull()
    {
        std::fill(m_data.begin(), m_data.end(), 0);
    }

    // COMMENT HOUSE: Comparisons. "operator==" defines what == means
    // for blobs: two blobs are equal when all their bytes are equal.
    // "= default" asks C++ to write that comparison automatically.
    constexpr bool operator==(const base_blob&) const = default;

    // COMMENT HOUSE: "operator<=>" (nicknamed the "spaceship operator")
    // defines <, >, <= and >= all at once. "Lexicographic" means dictionary
    // order: compare the first byte, and only if those are equal move on to
    // the next, just like comparing words letter by letter. Being able to sort
    // blobs is useful, for example, to keep them in sorted lists.
    /** Lexicographic ordering
     * @note Does NOT match the ordering on the corresponding \ref
     *       base_uint::CompareTo, which starts comparing from the end.
     */
    constexpr std::strong_ordering operator<=>(const base_blob& other) const = default;

    // COMMENT HOUSE: Showing a blob as hex text.
    // Hexadecimal ("hex") writes numbers in base 16, using the digits 0-9 and
    // the letters a-f. Each byte becomes exactly two hex characters, so a
    // 32-byte uint256 prints as 64 characters.
    //
    // The original comment below explains a famous Bitcoin quirk: hashes are
    // displayed with their bytes in REVERSE order. When you look up a block or
    // transaction ID in a block explorer, you are seeing this reversed form.
    // That is why block hashes are shown starting with lots of zeros, e.g. the
    // very first block's hash, 000000000019d6689c... (see
    // src/kernel/chainparams.cpp). Treated as a number, a block hash must be
    // small to satisfy proof of work, and a small number written normally
    // starts with zeros.
    /** @name Hex representation
     *
     * The hex representation used by GetHex(), ToString(), and FromHex()
     * is unusual, since it shows bytes of the base_blob in reverse order.
     * For example, a 4-byte blob {0x12, 0x34, 0x56, 0x78} is represented
     * as "78563412" instead of the more typical "12345678" representation
     * that would be shown in a hex editor or used by typical
     * byte-array / hex conversion functions like python's bytes.hex() and
     * bytes.fromhex().
     *
     * The nice thing about the reverse-byte representation, even though it is
     * unusual, is that if a blob contains an arithmetic number in little endian
     * format (with least significant bytes first, and most significant bytes
     * last), the GetHex() output will match the way the number would normally
     * be written in base-16 (with most significant digits first and least
     * significant digits last).
     *
     * This means, for example, that ArithToUint256(num).GetHex() can be used to
     * display an arith_uint256 num value as a number, because
     * ArithToUint256() converts the number to a blob in little-endian format,
     * so the arith_uint256 class doesn't need to have its own number parsing
     * and formatting functions.
     *
     * @{*/
    std::string GetHex() const;
    std::string ToString() const;
    /**@}*/

    // COMMENT HOUSE: Direct access to the raw bytes.
    //   - data() and begin() give the memory address of the first byte.
    //   - end() gives the address just past the last byte.
    // Having begin() and end() lets standard C++ tools (copying, looping,
    // etc.) work on a blob like on any other list. Each function appears
    // twice: the "const" version only lets you read the bytes, the other one
    // also lets you change them.
    constexpr const unsigned char* data() const { return m_data.data(); }
    constexpr unsigned char* data() { return m_data.data(); }

    constexpr unsigned char* begin() { return m_data.data(); }
    constexpr unsigned char* end() { return m_data.data() + WIDTH; }

    constexpr const unsigned char* begin() const { return m_data.data(); }
    constexpr const unsigned char* end() const { return m_data.data() + WIDTH; }

    // COMMENT HOUSE: size() returns the size in bytes (32 for uint256).
    static constexpr unsigned int size() { return WIDTH; }

    // COMMENT HOUSE: GetUint64(pos) reads 8 of the bytes as one 64-bit
    // number: pos 0 means bytes 0-7, pos 1 means bytes 8-15, and so on. "LE"
    // in ReadLE64 stands for "little endian": the first byte is treated as the
    // smallest part of the number. Because hash bytes look random, this is a
    // cheap way to get a random-looking number out of a hash (used, for
    // example, in src/blockfilter.cpp).
    constexpr uint64_t GetUint64(int pos) const { return ReadLE64(m_data.data() + pos * 8); }

    // COMMENT HOUSE: Serialize and Unserialize.
    // "Serializing" means turning an object into a row of bytes so it can be
    // saved to disk or sent over the network; "unserializing" turns those
    // bytes back into the object. For a blob it is simple: its bytes are
    // written or read exactly as they are. "template<typename Stream>" means
    // these work with any kind of "stream" (a file, a network message, ...).
    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s << std::span(m_data);
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read(MakeWritableByteSpan(m_data));
    }
};

// COMMENT HOUSE: The build-time hex constructor promised above.
// Step by step:
//   1. The text must be exactly two hex characters per byte, otherwise the
//      build fails with "Hex string must fit exactly".
//   2. rbegin() starts reading from the END of the text. This produces the
//      reversed byte order explained in the hex comment above.
//   3. For each byte, it reads two hex characters: the low digit (lo) and the
//      high digit. "<< 4" shifts the high digit into the top half of the byte,
//      and "|" combines it with the low digit. For example, the characters "a"
//      and "3" become the byte 0xa3.
// This is how the code can write a hash directly, like
// uint256{"000000000019d6689c..."} in src/kernel/chainparams.cpp.
template <unsigned int BITS>
consteval base_blob<BITS>::base_blob(std::string_view hex_str)
{
    if (hex_str.length() != m_data.size() * 2) throw "Hex string must fit exactly";
    auto str_it = hex_str.rbegin();
    for (auto& elem : m_data) {
        auto lo = util::ConstevalHexDigit(*(str_it++));
        elem = (util::ConstevalHexDigit(*(str_it++)) << 4) | lo;
    }
}

// COMMENT HOUSE: The "detail" namespace holds helper code that is
// meant to be used through uint160 and uint256 below, not directly.
namespace detail {
// COMMENT HOUSE: FromHex turns hex text into a blob while the program
// is RUNNING (unlike the build-time constructor above), for example when
// reading a hash someone typed in. It returns a std::optional: a box that
// either holds a result or is empty (std::nullopt) if the text was not valid.
// The caller must check which one it got, so bad input cannot slip through.
// The while loop reads the text from the end, two characters per byte, the
// same reversed order as above.
/**
 * Writes the hex string (in reverse byte order) into a new uintN_t object
 * and only returns a value iff all of the checks pass:
 *   - Input length is uintN_t::size()*2
 *   - All characters are hex
 */
template <class uintN_t>
std::optional<uintN_t> FromHex(std::string_view str)
{
    if (uintN_t::size() * 2 != str.size() || !IsHex(str)) return std::nullopt;
    uintN_t rv;
    unsigned char* p1 = rv.begin();
    unsigned char* pend = rv.end();
    size_t digits = str.size();
    while (digits > 0 && p1 < pend) {
        *p1 = ::HexDigit(str[--digits]);
        if (digits > 0) {
            *p1 |= ((unsigned char)::HexDigit(str[--digits]) << 4);
            p1++;
        }
    }
    return rv;
}
// COMMENT HOUSE: FromUserHex is a friendlier version of FromHex for
// text typed by people. It accepts an optional "0x" at the start (a common
// way of marking hex numbers) and allows leaving out leading zeros, just like
// you can write the number 007 as 7. It adds the missing zeros back and then
// uses FromHex.
/**
 * @brief Like FromHex(std::string_view str), but allows an "0x" prefix
 *        and pads the input with leading zeroes if it is shorter than
 *        the expected length of uintN_t::size()*2.
 *
 *        Designed to be used when dealing with user input.
 */
template <class uintN_t>
std::optional<uintN_t> FromUserHex(std::string_view input)
{
    input = util::RemovePrefixView(input, "0x");
    constexpr auto expected_size{uintN_t::size() * 2};
    if (input.size() < expected_size) {
        auto padded = std::string(expected_size, '0');
        std::copy(input.begin(), input.end(), padded.begin() + expected_size - input.size());
        return FromHex<uintN_t>(padded);
    }
    return FromHex<uintN_t>(input);
}
} // namespace detail

// COMMENT HOUSE: uint160, the 20-byte blob. ": public base_blob<160>"
// means uint160 is built on top of base_blob with BITS = 160, so it gets
// everything base_blob has, plus the extra functions listed here.
/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160> {
public:
    static std::optional<uint160> FromHex(std::string_view str) { return detail::FromHex<uint160>(str); }
    constexpr uint160() = default;
    constexpr explicit uint160(std::span<const unsigned char> vch) : base_blob<160>(vch) {}
};

// COMMENT HOUSE: uint256, the 32-byte blob and the one you will see
// most. It is base_blob<256> plus convenient ways to create one: from hex text
// (at run time or at build time), from a small number, or from raw bytes.
// ZERO and ONE are ready-made constants, all zeros and the value 1; they are
// set up in src/uint256.cpp.
/** 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256> {
public:
    static std::optional<uint256> FromHex(std::string_view str) { return detail::FromHex<uint256>(str); }
    static std::optional<uint256> FromUserHex(std::string_view str) { return detail::FromUserHex<uint256>(str); }
    constexpr uint256() = default;
    consteval explicit uint256(std::string_view hex_str) : base_blob<256>(hex_str) {}
    constexpr explicit uint256(uint8_t v) : base_blob<256>(v) {}
    constexpr explicit uint256(std::span<const unsigned char> vch) : base_blob<256>(vch) {}
    static const uint256 ZERO;
    static const uint256 ONE;
};

// COMMENT HOUSE: End of the header guard that started near the top.
#endif // BITCOIN_UINT256_H
