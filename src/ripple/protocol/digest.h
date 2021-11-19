//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012, 2013 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#ifndef RIPPLE_PROTOCOL_DIGEST_H_INCLUDED
#define RIPPLE_PROTOCOL_DIGEST_H_INCLUDED

#include <ripple/basics/base_uint.h>
#include <ripple/crypto/secure_erase.h>
#include <boost/endian/conversion.hpp>
#include <algorithm>
#include <array>
#include "ripple/beast/hash/xxhasher.h"

namespace ripple {

/** Message digest functions used in the codebase

    @note These are modeled to meet the requirements of `Hasher` in the
          `hash_append` interface, discussed in proposal:

          N3980 "Types Don't Know #"
          http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2014/n3980.html
*/

//------------------------------------------------------------------------------

/** RIPEMD-160 digest

    @note This uses the OpenSSL implementation
*/
struct openssl_ripemd160_hasher
{
public:
    static constexpr auto const endian = boost::endian::order::native;

    using result_type = std::array<std::uint8_t, 20>;

    openssl_ripemd160_hasher();

    void
    operator()(void const* data, std::size_t size) noexcept;

    explicit operator result_type() noexcept;

private:
    char ctx_[96];
};

/** SHA-512 digest

    @note This uses the OpenSSL implementation
*/
struct openssl_sha512_hasher
{
public:
    static constexpr auto const endian = boost::endian::order::native;

    using result_type = std::array<std::uint8_t, 64>;

    openssl_sha512_hasher();

    void
    operator()(void const* data, std::size_t size) noexcept;

    explicit operator result_type() noexcept;

private:
    char ctx_[216];
};

/** SHA-256 digest

    @note This uses the OpenSSL implementation
*/
struct openssl_sha256_hasher
{
public:
    static constexpr auto const endian = boost::endian::order::native;

    using result_type = std::array<std::uint8_t, 32>;

    openssl_sha256_hasher();

    void
    operator()(void const* data, std::size_t size) noexcept;

    explicit operator result_type() noexcept;

private:
    char ctx_[112];
};

//------------------------------------------------------------------------------

using ripemd160_hasher = openssl_ripemd160_hasher;
using sha256_hasher = openssl_sha256_hasher;
using sha512_hasher = openssl_sha512_hasher;

//------------------------------------------------------------------------------

/** Returns the RIPEMD-160 digest of the SHA256 hash of the message.

    This operation is used to compute the 160-bit identifier
    representing a Ripple account, from a message. Typically the
    message is the public key of the account - which is not
    stored in the account root.

    The same computation is used regardless of the cryptographic
    scheme implied by the public key. For example, the public key
    may be an ed25519 public key or a secp256k1 public key. Support
    for new cryptographic systems may be added, using the same
    formula for calculating the account identifier.

    Meets the requirements of Hasher (in hash_append)
*/
struct ripesha_hasher
{
private:
    sha256_hasher h_;

public:
    static constexpr auto const endian = boost::endian::order::native;

    using result_type = std::array<std::uint8_t, 20>;

    void
    operator()(void const* data, std::size_t size) noexcept
    {
        h_(data, size);
    }

    explicit operator result_type() noexcept
    {
        auto const d0 = sha256_hasher::result_type(h_);
        ripemd160_hasher rh;
        rh(d0.data(), d0.size());
        return ripemd160_hasher::result_type(rh);
    }
};

//------------------------------------------------------------------------------

namespace detail {

/** Returns the SHA512-Half digest of a message.

    The SHA512-Half is the first 256 bits of the
    SHA-512 digest of the message.
*/
template <bool Secure>
struct basic_sha512_half_hasher
{
private:
    sha512_hasher h_;

public:
    static constexpr auto const endian = boost::endian::order::big;

    using result_type = uint256;

    ~basic_sha512_half_hasher()
    {
        erase(std::integral_constant<bool, Secure>{});
    }

    void
    operator()(void const* data, std::size_t size) noexcept
    {
        h_(data, size);
    }

    explicit operator result_type() noexcept
    {
        auto const digest = sha512_hasher::result_type(h_);
        return result_type::fromVoid(digest.data());
    }

private:
    inline void erase(std::false_type)
    {
    }

    inline void erase(std::true_type)
    {
        secure_erase(&h_, sizeof(h_));
    }
};

}  // namespace detail

using sha512_half_hasher = detail::basic_sha512_half_hasher<false>;

// secure version
using sha512_half_hasher_s = detail::basic_sha512_half_hasher<true>;

//------------------------------------------------------------------------------


class xorhasher
{
private:
    // requires 64-bit std::size_t
    static_assert(sizeof(std::size_t) == 8, "");


    size_t size_ = 0;
    size_t hash_ = 0;
    

public:
    using result_type = std::size_t;

    static constexpr auto const endian = boost::endian::order::native;

    explicit xorhasher(uint64_t seed)
    {
        hash_ = seed;
    }
    void
    operator()(void const* key, std::size_t len) noexcept
    {
        int i = 0;
        for (i = 0; i < len; i+= 8)
            hash_ ^= *(reinterpret_cast<const uint64_t*>(key + i));

        for (; i < len; ++i)
        {
            hash_ ^= *(reinterpret_cast<const uint8_t*>(key + i));
            hash_ = (hash_ >> 8U) | (hash_ << 56U);
        }

        hash_ = (hash_ >> 8U) | (hash_ << 56U);
        hash_ ++;

        size_ += len;
    }

    size_t get_hash() noexcept
    {
        return hash_;
    }

    size_t get_size() noexcept
    {
        return size_;
    }

};


//#define DEBUG_CACHE 1
#define CACHE_BUCKET_COUNT 0x100000U  // size of the cache
#define CACHE_THRESHOLD_COUNT 10000U  // the number of times sha512h needs to be called on this thread before stats
                                      // about effectiveness can be computed
#define CACHE_THRESHOLD_RATE 5.0f     // if the % of hits falls below this value [0 - 100] then skip cache altogether

/** Returns the SHA512-Half of a series of objects. */
template <class... Args>
sha512_half_hasher::result_type
sha512Half(Args const&... args)
{
    using beast::hash_append;

    static thread_local uint64_t miss_count = 0;
    static thread_local uint64_t total_count = 0;
    static thread_local std::unordered_map<size_t, uint256> seen { CACHE_BUCKET_COUNT };
    static thread_local uint64_t thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id());

    double rate = (100.0f - (((double)(miss_count))/((double)(total_count))*100.0f));


    if (total_count % 1000 == 999)
        printf("Cache performance. Thread ID = %llu, Hit rate = %g%%\n", thread_id, rate);

    total_count++;

    if (total_count > CACHE_THRESHOLD_COUNT && rate < CACHE_THRESHOLD_RATE)
    {
        // skip caching altogether this thread doesn't need benefit from it
        sha512_half_hasher h;
        hash_append(h, args...);
        return static_cast<typename sha512_half_hasher::result_type>(h);
    }

    // otherwise continue and do a cache lookup and possibly a cache write

#ifdef DEBUG_CACHE
    uint64_t dur1 = 0, dur2 = 0;
    {
        unsigned int lo,hi;
        __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
        dur1 = ((uint64_t)hi << 32) | lo;
    }
#endif

    xorhasher x { thread_id };
    hash_append(x, args...);
    size_t cache_id = x.get_hash();
    size_t size = x.get_size();

    bool cache_hit = 
            seen.find(cache_id) != seen.end();
#ifdef DEBUG_CACHE
    {
        unsigned int lo,hi;
        __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));

        dur2 = ((uint64_t)hi << 32) | lo;
        dur1 = dur2 - dur1;
    }
#endif

    if (cache_hit)
    {

#ifdef DEBUG_CACHE    
        printf(
                "thread=%llX\tHIT  : sha512h "
                "cycles {sha=%llu\txx=%llu}\t\tsize=%llu\tcache_hits=%02.02g%%\tcache_id=%llx\n",
                thread_id,
                0, dur1,
                size, rate,
                cache_id);
#endif        
        return seen[cache_id];
    }

    miss_count++;
    sha512_half_hasher h;
    hash_append(h, args...);
    auto r = static_cast<typename sha512_half_hasher::result_type>(h);
    
#ifdef DEBUG_CACHE    
    {
        unsigned int lo,hi;
        __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
        dur2 = (((uint64_t)hi << 32) | lo) - dur2;
    }
    printf(
            "thread=%llX\tMISS : sha512h "
            "cycles {sha=%llu\txx=%llu}\t\tsize=%llu\tcache_hits=%02.02g%%\tcache_id=%llx\n",
            thread_id,
            dur2, dur1, 
            size, rate,
            cache_id);
#endif

    // prune the map when it gets too big
    if (seen.size() >= CACHE_BUCKET_COUNT)
        seen.erase(seen.begin());

    seen.emplace(cache_id, r);

    return r;
}

/** Returns the SHA512-Half of a series of objects.

    Postconditions:
        Temporary memory storing copies of
        input messages will be cleared.
*/
template <class... Args>
sha512_half_hasher_s::result_type
sha512Half_s(Args const&... args)
{
    sha512_half_hasher_s h;
    using beast::hash_append;
    hash_append(h, args...);
    return static_cast<typename sha512_half_hasher_s::result_type>(h);
}

}  // namespace ripple

#endif
