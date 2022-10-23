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

#include <ripple/basics/contract.h>
#include <ripple/nodestore/Factory.h>
#include <ripple/nodestore/Manager.h>
#include <ripple/nodestore/impl/DecodedBlob.h>
#include <ripple/nodestore/impl/EncodedBlob.h>
#include <ripple/nodestore/impl/codec.h>
#include <boost/filesystem.hpp>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <lmdb/lmdb++.h>

namespace ripple {
namespace NodeStore {

class LMDBBackend : public Backend
{
public:

    std::string const name_;
    lmdb::env env_;
    bool open_ = false;

    LMDBBackend(std::string name):name_(name), env_( lmdb::env::create() )
    {
    }

    std::string
    getName() override
    {
        return name_;
    }

    bool
    isOpen() override
    {
        return open_;
    }

    void
    open(bool createIfMissing) override
    {
        using namespace boost::filesystem;
        auto const folder = path(name_);
        auto const fn = (folder).string();
        if (createIfMissing)
            create_directories(folder.string());

        env_.set_mapsize(10UL * 1024UL * 1024UL * 1024UL * 1024UL);
        env_.open(fn.c_str(), 0, 0664);
        open_ = true;
    }

    void
    close() override
    {
        if (env_)
        {
            env_.close();
            open_ = false;
        }
    }

    Status
    fetch(void const* key_raw, std::shared_ptr<NodeObject>* pno) override
    {
        pno->reset();

        auto rtxn = lmdb::txn::begin(env_, nullptr); //, MDB_RDONLY);
        auto dbi = lmdb::dbi::open(rtxn, nullptr);

        std::string_view value;
        std::string_view key((const char*)key_raw, (size_t)32U);

        if (dbi.get(rtxn, key, value))
        {
            nudb::detail::buffer bf;
            auto const result = nodeobject_decompress(value.data(), value.size(), bf);
            DecodedBlob decoded(key_raw, result.first, result.second);
            if (!decoded.wasOk())
                return dataCorrupt;
            *pno = decoded.createObject();
            return ok;
        }
        else
            return notFound;
    }

    std::pair<std::vector<std::shared_ptr<NodeObject>>, Status>
    fetchBatch(std::vector<uint256 const*> const& hashes) override
    {
        std::vector<std::shared_ptr<NodeObject>> results;
        results.reserve(hashes.size());
        for (auto const& h : hashes)
        {
            std::shared_ptr<NodeObject> nObj;
            Status status = fetch(h->begin(), &nObj);
            if (status != ok)
                results.push_back({});
            else
                results.push_back(nObj);
        }

        return {results, ok};
    }

    void
    store(std::shared_ptr<NodeObject> const& no) override
    {
        EncodedBlob e;
        e.prepare(no);
        nudb::detail::buffer bf;
        auto const result = nodeobject_compress(e.getData(), e.getSize(), bf);
        auto wtxn = lmdb::txn::begin(env_);
        auto dbi = lmdb::dbi::open(wtxn, nullptr);
        
        std::string_view key( 
            (const char*)(e.getKey()), (size_t)32U );
        std::string_view value(
            (const char*)(result.first), (size_t)result.second );
        dbi.put(wtxn, key, value);
        wtxn.commit();
    }


    void
    storeBatch(Batch const& batch) override
    {
        for (auto const& e : batch)
            store(e);
    }

    void
    sync() override
    {
    }

    void
    for_each(std::function<void(std::shared_ptr<NodeObject>)> f) override
    {
        auto rtxn = lmdb::txn::begin(env_, nullptr); //, MDB_RDONLY);
        auto dbi = lmdb::dbi::open(rtxn, nullptr);
        auto cursor = lmdb::cursor::open(rtxn, dbi);
        std::string_view key;
        std::string_view value;
        while (cursor.get(key, value, MDB_NEXT))
        {
            nudb::detail::buffer bf;
            auto const result = nodeobject_decompress(value.data(), value.size(), bf);
            DecodedBlob decoded(key.data(), result.first, result.second);
            if (!decoded.wasOk())
                Throw<std::runtime_error>("lmdb value missing");

            f(decoded.createObject());
        }
    }

    int
    getWriteLoad() override
    {
        return 0;
    }

    void
    setDeletePath() override
    {
    }

    int
    fdRequired() const override
    {
        return 3;
    }
};

//------------------------------------------------------------------------------

class LMDBFactory : public Factory
{
public:
    LMDBFactory()
    {
        Manager::instance().insert(*this);
    }

    ~LMDBFactory() override
    {
        Manager::instance().erase(*this);
    }

    std::string
    getName() const override
    {
        return "lmdb";
    }

    std::unique_ptr<Backend>
    createInstance(
        size_t keyBytes,
        Section const& keyValues,
        std::size_t burstSize,
        Scheduler& scheduler,
        beast::Journal journal) override
    {


        return std::make_unique<LMDBBackend>(
                get(keyValues, "path")
        );
    }
};

static LMDBFactory lmdbFactory;

}  // namespace NodeStore
}  // namespace ripple
