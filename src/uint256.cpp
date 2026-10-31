// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// COMMENT HOUSE: What is this file?
// A small companion to uint256.h: the code for turning a 160-bit or
// 256-bit value into hexadecimal text.
#include <uint256.h>

#include <util/strencodings.h>

// COMMENT HOUSE: GetHex() prints the bytes in REVERSE order. Bitcoin stores
// hashes "little-endian" (smallest byte first), but by tradition shows them
// the other way round. That is why block hashes are displayed with their
// zeros at the START, like 000000000019d6..., even though the zero bytes
// are stored at the END in memory.
template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const
{
    uint8_t m_data_rev[WIDTH];
    for (int i = 0; i < WIDTH; ++i) {
        m_data_rev[i] = m_data[WIDTH - 1 - i];
    }
    return HexStr(m_data_rev);
}

template <unsigned int BITS>
std::string base_blob<BITS>::ToString() const
{
    return (GetHex());
}

// Explicit instantiations for base_blob<160>
// COMMENT HOUSE: Templates normally live in header files. These lines tell
// the compiler to build the 160-bit and 256-bit versions here, once, so
// other files can use them.
template std::string base_blob<160>::GetHex() const;
template std::string base_blob<160>::ToString() const;

// Explicit instantiations for base_blob<256>
template std::string base_blob<256>::GetHex() const;
template std::string base_blob<256>::ToString() const;

// COMMENT HOUSE: Two handy constants: the numbers 0 and 1 as uint256 values.
const uint256 uint256::ZERO(0);
const uint256 uint256::ONE(1);
