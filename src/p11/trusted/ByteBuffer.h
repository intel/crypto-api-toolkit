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

#ifndef BYTE_BUFFER_H
#define BYTE_BUFFER_H

#include "Constants.h"

#include <string>

namespace CryptoSgx
{
    /**
     * Class used to handle a byte buffer.
     */
    class ByteBuffer
    {
    public:
        /**
         * Default Constructor.
         */
        ByteBuffer();

        /**
         * Copy Constructor.
         * @param other  Another ByteBuffer to be copied.
         */
        ByteBuffer(const ByteBuffer& other);

        /**
         * Copy Assignment.
         * @param   other   The ByteBuffer to be assigned to this one.
         * @return          A reference to this object.
         */
        ByteBuffer& operator=(const ByteBuffer& other);

        /**
         * Constructor by size.
         * @param size  The size of the buffer.
         */
        ByteBuffer(const size_t size);

        /**
         * Constructor - Copy data.
         * @param data  A pointer to the data to be copied into the buffer.
         * @param size  The size of data to be copied into the buffer.
         */
        ByteBuffer(const Byte* data, const size_t size);

        /**
         * Destructor.
         */
        ~ByteBuffer();

        /**
         * Allocates a buffer and copies the content of data.
         * @param data  A pointer to the data to be copied into the buffer.
         * @param size  The size of data to be copied into the buffer.
         */
        void fromData(const Byte* data, const size_t size);

        /**
         * Copies the ByteBuffer into a raw buffer data.
         * @param   buffer        A pointer to a raw buffer where the buffer will be copied into.
         * @param   bufferSize    The size of the buffer.
         * @return                True if the data was copied into the buffer, false otherwise.
         */
        void toData(Byte* buffer, const size_t bufferSize) const;

        /**
         * Allocates a buffer (previous content will be deleted).
         * @param size  The size of the buffer to be allocated.
         */
        void allocate(const size_t size);

        /**
         * Gets the size of the buffer.
         * @return The size of the buffer.
         */
        size_t size() const;

        /**
         * Gets a pointer to the buffer being handled.
         * @return A pointer to the buffer being handled.
         */
        Byte* get();

        /*
         * Gets a const pointer to the buffer being handled.
         * @return A const pointer to the buffer being handled.
         */
        const Byte* get() const;

        /**
         * Checks if the buffer is valid.
         * @return True if the buffer is valid, false otherwise.
         */
        bool isValid() const;

        /**
         * Access/Modifies elements on the buffer.
         * @param   index  The index of the element to be accessed.
         * @return         A reference of the element pointed out.
         */
        Byte& operator[](const size_t index);

        /**
         * Read-only access elements on the buffer.
         * @param   index  The index of the element to be accessed.
         * @return         A reference of the element pointed out.
         */
        const Byte& operator[](const size_t index) const;

        /**
         * Converts the content of the buffer into a string representation.
         * @return A string containing the content of the buffer.
         */
        std::string toString() const;

    private:
        void release();

        // Member variables
        size_t mSize;
        Byte*  mBuffer;
    };

} //CryptoSgx

#endif //BYTE_BUFFER_H

