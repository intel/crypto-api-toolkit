/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "ByteBuffer.h"

#include <mbusafecrt.h>

namespace CryptoSgx
{
    //---------------------------------------------------------------------------------------------
    ByteBuffer::ByteBuffer()
        : mSize(0)
        , mBuffer(nullptr)
    {
    }

    //---------------------------------------------------------------------------------------------
    ByteBuffer::ByteBuffer(const ByteBuffer& other)
        : mSize(0)
        , mBuffer(nullptr)
    {
        fromData(other.mBuffer, other.mSize);
    }

    //---------------------------------------------------------------------------------------------
    ByteBuffer& ByteBuffer::operator=(const ByteBuffer& other)
    {
        if (this->mBuffer != other.get())
        {
            fromData(other.mBuffer, other.mSize);
        }
        return *this;
    }

    //---------------------------------------------------------------------------------------------
    ByteBuffer::ByteBuffer(const size_t size)
        : mSize(size)
        , mBuffer(nullptr)
    {
        allocate(size);
    }

    //---------------------------------------------------------------------------------------------
    ByteBuffer::ByteBuffer(const Byte* data, const size_t size)
        : mSize(size)
        , mBuffer(nullptr)
    {
        allocate(size);
        memcpy_s(mBuffer, mSize, data, size);
    }

    //---------------------------------------------------------------------------------------------
    ByteBuffer::~ByteBuffer()
    {
        release();
    }

    //---------------------------------------------------------------------------------------------
    void ByteBuffer::fromData(const Byte* data, const size_t size)
    {
        allocate(size);
        memcpy_s(mBuffer, mSize, data, size);
    }

    //---------------------------------------------------------------------------------------------
    void ByteBuffer::toData(Byte* buffer, const size_t bufferSize) const
    {
        memcpy_s(buffer, bufferSize, mBuffer, mSize);
    }

    //---------------------------------------------------------------------------------------------
    void ByteBuffer::allocate(const size_t size)
    {
        if (isValid())
        {
            release();
        }
        mSize = size;
        mBuffer = new Byte[mSize];
    }

    //---------------------------------------------------------------------------------------------
    void ByteBuffer::release()
    {
        mSize = 0;
        delete[] mBuffer;
        mBuffer = nullptr;
    }

    //---------------------------------------------------------------------------------------------
    size_t ByteBuffer::size() const
    {
        return mSize;
    }

    //---------------------------------------------------------------------------------------------
    Byte* ByteBuffer::get()
    {
        return mBuffer;
    }

    //---------------------------------------------------------------------------------------------
    const Byte* ByteBuffer::get() const
    {
        return mBuffer;
    }

    //---------------------------------------------------------------------------------------------
    bool ByteBuffer::isValid() const
    {
        return mBuffer != nullptr;
    }

    //---------------------------------------------------------------------------------------------
    Byte& ByteBuffer::operator[](const size_t index)
    {
        return mBuffer[index];
    }

    //---------------------------------------------------------------------------------------------
    const Byte& ByteBuffer::operator[](const size_t index) const
    {
        return mBuffer[index];
    }

    //---------------------------------------------------------------------------------------------
    std::string ByteBuffer::toString() const
    {
        std::string result;
        for (size_t index = 0; index < mSize; index++)
        {
            result += mBuffer[index];
        }
        return result;
    }

} //CryptoSgx