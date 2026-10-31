// Copyright (c) 2017, 2021 Pieter Wuille
// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bech32 and Bech32m are string encoding formats used in newer
// address types. The outputs consist of a human-readable part
// (alphanumeric), a separator character (1), and a base32 data
// section, the last 6 characters of which are a checksum. The
// module is namespaced under bech32 for historical reasons.
//
// For more information, see BIP 173 and BIP 350.

// COMMENT HOUSE: What is this file?
// It announces the bech32 functions. The developer comment above already
// gives the format: human-readable part + "1" + data, ending in a
// 6-character checksum. The full explanation is in bech32.cpp, and the code
// that turns addresses into bech32 text is in key_io.cpp.
//
// Header guard: makes sure this file is only read once, even if many other
// files include it. It ends at the #endif at the bottom.
#ifndef BITCOIN_BECH32_H
#define BITCOIN_BECH32_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace bech32
{

inline constexpr size_t CHECKSUM_SIZE = 6;
inline constexpr char SEPARATOR = '1';

// COMMENT HOUSE: Which version a string uses: Bech32 (BIP 173, SegWit
// version 0) or Bech32m (BIP 350, Taproot and later). INVALID means the
// checksum did not match either.
enum class Encoding {
    INVALID, //!< Failed decoding

    BECH32,  //!< Bech32 encoding as defined in BIP173
    BECH32M, //!< Bech32m encoding as defined in BIP350
};

/** Character limits for Bech32(m) encoded strings. Character limits are how we provide error location guarantees.
 *  These values should never exceed 2^31 - 1 (max value for a 32-bit int), since there are places where we may need to
 *  convert the CharLimit::VALUE to an int. In practice, this should never happen since this CharLimit applies to an address encoding
 *  and we would never encode an address with such a massive value */
// COMMENT HOUSE: Maximum lengths. Normal addresses may be at most 90
// characters, the length for which the checksum is guaranteed to catch up
// to 4 mistakes. Silent payment addresses (BIP 352) are longer, so they get
// their own limit.
enum CharLimit : size_t {
    BECH32 = 90,            //!< BIP173/350 imposed character limit for Bech32(m) encoded addresses. This guarantees finding up to 4 errors.
    SILENT_PAYMENTS = 1023, //!< BIP352 imposed 1023 character limit on Bech32m encoded silent payment addresses. This guarantees finding up to 3 errors.
};

/** Encode a Bech32 or Bech32m string. If hrp contains uppercase characters, this will cause an
 *  assertion error. Encoding must be one of BECH32 or BECH32M. */
std::string Encode(Encoding encoding, const std::string& hrp, const std::vector<uint8_t>& values);

// COMMENT HOUSE: What Decode() returns: which encoding was found, the
// human-readable part (such as "bc"), and the data values without the
// checksum.
struct DecodeResult
{
    Encoding encoding;         //!< What encoding was detected in the result; Encoding::INVALID if failed.
    std::string hrp;           //!< The human readable part
    std::vector<uint8_t> data; //!< The payload (excluding checksum)

    DecodeResult() : encoding(Encoding::INVALID) {}
    DecodeResult(Encoding enc, std::string&& h, std::vector<uint8_t>&& d) : encoding(enc), hrp(std::move(h)), data(std::move(d)) {}
};

/** Decode a Bech32 or Bech32m string. */
DecodeResult Decode(const std::string& str, CharLimit limit = CharLimit::BECH32);

/** Return the positions of errors in a Bech32 string. */
std::pair<std::string, std::vector<int>> LocateErrors(const std::string& str, CharLimit limit = CharLimit::BECH32);

} // namespace bech32

#endif // BITCOIN_BECH32_H
