/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this vector of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this vector of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 File.h

 This class wraps standard C file I/O in a convenient way for the object store
 *****************************************************************************/


#include "config.h"
#include "File.h"
#include <string>
#include <string.h>
#ifndef SGXHSM
#include <stdio.h>
#ifndef _WIN32
#include <sys/file.h>
#include <unistd.h>
#else
#include <io.h>
#define F_SETLK		12
#define F_SETLKW	13
#define F_RDLCK		1
#define F_UNLCK		2
#define F_WRLCK		3
#endif
#include <sys/stat.h>
#include <fcntl.h>
#else
#include "sgx_tprotected_fs.h"
#endif
#include <errno.h>

#define MAX_FOPEN_RETRIES 200

enum AttributeKind {
	akUnknown,
	akBoolean,
	akInteger,
	akBinary,
	akAttrMap,
	akMechSet
};

// Constructor
//
// N.B.: the create flag only has a function when a file is opened read/write
// N.B.: the truncate flag only has a function when the create one is true
#ifndef SGXHSM
File::File(std::string inPath, bool forRead /* = true */, bool forWrite /* = false */, bool create /* = false */, bool truncate /* = true */)
{
	stream = NULL;

	isReadable = forRead;
	isWritable = forWrite;
	locked = false;

	path = inPath;
	valid = false;


	if (forRead || forWrite)
	{
		std::string fileMode = "";
		int flags, fd;

#ifndef _WIN32
		flags = 0;
		if (forRead && !forWrite) flags |= O_RDONLY;
		if (!forRead && forWrite) flags |= O_WRONLY | O_CREAT | O_TRUNC;
		if (forRead && forWrite) flags |= O_RDWR;
		if (forRead && forWrite && create) flags |= O_CREAT;
		if (forRead && forWrite && create && truncate) flags |= O_TRUNC;
		// Open the file
		fd = open(path.c_str(), flags, 0600);
		if (fd == -1)
		{
			// ERROR_MSG("Could not open the file (%s): %s", strerror(errno), path.c_str());
			valid = false;
			return;
		}

		if (forRead && !forWrite) fileMode = "r";
		if (!forRead && forWrite) fileMode = "w";
		if (forRead && forWrite && !create) fileMode = "r+";
		if (forRead && forWrite && create) fileMode = "w+";
		// Open the stream
		valid = ((stream = fdopen(fd, fileMode.c_str())) != NULL);
#else
		flags = _O_BINARY;
		if (forRead && !forWrite) flags |= _O_RDONLY;
		if (!forRead && forWrite) flags |= _O_WRONLY | _O_CREAT | _O_TRUNC;
		if (forRead && forWrite) flags |= _O_RDWR;
		if (forRead && forWrite && create) flags |= _O_CREAT;
		if (forRead && forWrite && create && truncate) flags |= _O_TRUNC;
		// Open the file
		fd = _open(path.c_str(), flags, _S_IREAD | _S_IWRITE);
		if (fd == -1)
		{
			// ERROR_MSG("Could not open the file (%s): %s", strerror(errno), path.c_str());
			valid = false;
			return;
		}

		if (forRead && !forWrite) fileMode = "rb";
		if (!forRead && forWrite) fileMode = "wb";
		if (forRead && forWrite && !create) fileMode = "rb+";
		if (forRead && forWrite && create) fileMode = "wb+";
		// Open the stream
		valid = ((stream = _fdopen(fd, fileMode.c_str())) != NULL);
#endif
	}
}
#else
File::File(std::string inPath, bool forRead /* = true */, bool forWrite /* = false */, bool create /* = false */, bool truncate /* = true */)
{
	stream = NULL;

	isReadable = forRead;
	isWritable = forWrite;
	locked = false;

	path = inPath;
	valid = false;

	stream = sgx_fopen_auto_key(path.c_str(), "rb");
    if (!stream && (ENOENT == errno))
    {
        for (auto i = 0; i < MAX_FOPEN_RETRIES; ++i)
        {
            sgx_fclose(stream);
            stream = sgx_fopen_auto_key(path.c_str(), "rb");
            if (stream)
            {
                break;
            }
        }
    }

    std::string fileMode = "";
    if (stream || (EWOULDBLOCK == errno))
	{
		sgx_fclose(stream);
		fileMode = "rb+";
	}
	else
	{
		fileMode = "wb+";
	}

    valid = ((stream = sgx_fopen_auto_key(path.c_str(), reinterpret_cast<const char*>(fileMode.c_str()))) != nullptr);

    while (!valid && (EWOULDBLOCK == errno))
    {
        sgx_fclose(stream);
        valid = ((stream = sgx_fopen_auto_key(path.c_str(), reinterpret_cast<const char*>(fileMode.c_str()))) != nullptr);
    }

}
#endif

// Destructor
File::~File()
{
	if (locked)
	{
		unlock();
	}

	if (stream != NULL)
	{
#ifdef SGXHSM
		sgx_fclose(stream);
#else
		fclose(stream);
#endif
	}
}

// Check if the file is valid
bool File::isValid()
{
	return valid;
}

// Check if the file is readable
bool File::isRead()
{
	return isReadable;
}

// Check if the file is writable
bool File::isWrite()
{
	return isWritable;
}

// Check if the file is empty
bool File::isEmpty()
{
#ifdef SGXHSM
	bool result = false;
	if (valid)
	{
		sgx_fseek(stream, 0L, SEEK_END);
		if (0 == sgx_ftell(stream))
		{
			result = true;
		}
		else
		{
			result = false;
		}
	}
	rewind();

	return result;
#else
#ifndef _WIN32
	struct stat s;

	if (fstat(fileno(stream), &s) != 0)
	{
		valid = false;

		return false;
	}

	return (s.st_size == 0);
#else
	struct _stat s;

	if (_fstat(_fileno(stream), &s) != 0)
	{
		valid = false;

		return false;
	}

	return (s.st_size == 0);
#endif
#endif
}

// Check if the end-of-file was reached
bool File::isEOF()
{
#ifdef SGXHSM
	bool result = valid && sgx_feof(stream);
	return result;
#else
	return valid && feof(stream);
#endif
}

// Read an unsigned long value; warning: not thread safe without locking!
bool File::readULong(unsigned long& value)
{
	if (!valid) return false;

	ByteString ulongVal;

	ulongVal.resize(8);

#ifdef SGXHSM
	unsigned long readBytes = sgx_fread(&value, 1, sizeof(value), stream);
	if (readBytes != sizeof(value))
	{
		return false;
	}
#else
	if (fread(&ulongVal[0], 1, 8, stream) != 8)
	{
		return false;
	}

	value = ulongVal.long_val();
#endif

	return true;
}

// Read a ByteString value; warning: not thread safe without locking!
bool File::readByteString(ByteString& value)
{
	if (!valid) return false;

	// Retrieve the length to read from the file
	unsigned long len;

	if (!readULong(len))
	{
		return false;
	}

	// Read the byte string from the file
	value.resize(len);

	if (len == 0)
	{
		return true;
	}
#ifdef SGXHSM
	if (sgx_fread(&value[0], 1, len, stream) != len)
#else
	if (fread(&value[0], 1, len, stream) != len)
#endif	
	{
		return false;
	}

	return true;
}

// Read a boolean value; warning: not thread safe without locking!
bool File::readBool(bool& value)
{
	if (!valid) return false;

	// Read the boolean from the file
	unsigned char boolValue;

#ifdef SGXHSM
	if (sgx_fread(&boolValue, 1, 1, stream) != 1)
#else
	if (fread(&boolValue, 1, 1, stream) != 1)
#endif	
	{
		return false;
	}

	value = boolValue ? true : false;

	return true;
}

// Read a mechanism type set value; warning: not thread safe without locking!
bool File::readMechanismTypeSet(std::set<CK_MECHANISM_TYPE>& value)
{
	if (!valid) return false;

	unsigned long count;
	if (!readULong(count)) return false;

	for (unsigned long i = 0; i < count; i++)
	{
		unsigned long mechType;
		if (!readULong(mechType))
		{
			return false;
		}

		value.insert((CK_MECHANISM_TYPE) mechType);
	}

	return true;
}

// Read an attribute map value; warning: not thread safe without locking!
bool File::readAttributeMap(std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& value)
{
	if (!valid) return false;

	// Retrieve the length to read from the file
	unsigned long len;

	if (!readULong(len))
	{
		return false;
	}

	while (len != 0)
	{
		unsigned long attrType;
		if (!readULong(attrType))
		{
			return false;
		}
		if (8 > len)
		{
			return false;
		}
		len -= 8;

		unsigned long attrKind;
		if (!readULong(attrKind))
		{
			return false;
		}
		if (8 > len)
		{
			return false;
		}
		len -= 8;

		switch (attrKind)
		{
			case akBoolean:
			{
				bool val;
				if (!readBool(val))
				{
					return false;
				}
				if (1 > len)
				{
					return false;
				}
				len -= 1;

				value.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attrType, val));
			}
			break;

			case akInteger:
			{
				unsigned long val;
				if (!readULong(val))
				{
					return false;
				}
				if (8 > len)
				{
					return false;
				}
				len -= 8;

				value.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attrType, val));
			}
			break;

			case akBinary:
			{
				ByteString val;
				if (!readByteString(val))
				{
					return false;
				}
				if (8 + val.size() > len)
				{
					return false;
				}
				len -= 8 + val.size();

				value.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attrType, val));
			}
			break;

			case akMechSet:
			{
				std::set<CK_MECHANISM_TYPE> val;
				if (!readMechanismTypeSet(val))
				{
					return false;
				}
				if (8 + val.size() * 8 > len)
				{
					return false;
				}
				len -= 8 + val.size() * 8;

				value.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attrType, val));
			}
			break;

			default:
				return false;
		}
	}

	return true;
}

// Read a string value; warning: not thread safe without locking!
bool File::readString(std::string& value)
{
	if (!valid) return false;

	// Retrieve the length to read from the file
	unsigned long len;

	if (!readULong(len))
	{
		return false;
	}

	// Read the string from the file
	value.resize(len);

#ifdef SGXHSM
	if (sgx_fread(&value[0], 1, len, stream) != len)
#else
	if (fread(&value[0], 1, len, stream) != len)
#endif	
	{
		return false;
	}

	return true;
}

// Write an unsigned long value; warning: not thread safe without locking!
bool File::writeULong(const unsigned long value)
{
	if (!valid) return false;

	ByteString toWrite(value);

	// Write the value to the file
#ifdef SGXHSM
	if (sgx_fwrite(&value, 1, sizeof(value), stream) != sizeof(value))
#else
	if (fwrite(toWrite.const_byte_str(), 1, toWrite.size(), stream) != toWrite.size())
#endif	
	{
		return false;
	}

	flush();
	return true;
}

// Write a ByteString value; warning: not thread safe without locking!
bool File::writeByteString(const ByteString& value)
{
	if (!valid) return false;


	// Write the value to the file
#ifdef SGXHSM
	size_t len = value.size();
	if (sgx_fwrite(&len, 1, sizeof(len), stream) != sizeof(len))
	{
		return false;
	}

	if (sgx_fwrite(value.const_byte_str(), 1, value.size(), stream) != value.size())
	{
		return false;
	}
#else
	ByteString toWrite = value.serialise();
	if (fwrite(toWrite.const_byte_str(), 1, toWrite.size(), stream) != toWrite.size())
	{
		return false;
	}	
#endif	


	flush();

	return true;
}

// Write a string value; warning: not thread safe without locking!
bool File::writeString(const std::string& value)
{
	if (!valid) return false;

	ByteString toWrite((const unsigned long) value.size());
	
	// Write the value to the file
#ifdef SGXHSM
	if ((sgx_fwrite(toWrite.const_byte_str(), 1, toWrite.size(), stream) != toWrite.size()) ||
	    (sgx_fwrite(&value[0], 1, value.size(), stream) != value.size()))
#else	
	if ((fwrite(toWrite.const_byte_str(), 1, toWrite.size(), stream) != toWrite.size()) ||
	    (fwrite(&value[0], 1, value.size(), stream) != value.size()))
#endif
	{
		return false;
	}

	flush();
		return true;
}

// Write a mechanism type set value; warning: not thread safe without locking!
bool File::writeMechanismTypeSet(const std::set<CK_MECHANISM_TYPE>& value)
{
	if (!valid) return false;

	// write length
	if (!writeULong(value.size()))
	{
		return false;
	}

	// write each value
	for (std::set<CK_MECHANISM_TYPE>::const_iterator i = value.begin(); i != value.end(); ++i)
	{
		if (!writeULong(*i)) return false;
	}

	flush();
		return true;
}

// Write an attribute map value; warning: not thread safe without locking!
bool File::writeAttributeMap(const std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& value)
{
	if (!valid) return false;

	// compute length
	unsigned long len = 0;
	for (std::map<CK_ATTRIBUTE_TYPE,OSAttribute>::const_iterator i = value.begin(); i != value.end(); ++i)
	{
		OSAttribute attr = i->second;
		// count attribute type and kind
		len += 8 + 8;

		if (attr.isBooleanAttribute())
		{
			len += 1;
		}
		else if (attr.isUnsignedLongAttribute())
		{
			len += 8;
		}
		else if (attr.isByteStringAttribute())
		{
			ByteString val = attr.getByteStringValue();
			len += 8 + val.size();
		}
		else if (attr.isMechanismTypeSetAttribute())
		{
			std::set<CK_MECHANISM_TYPE> val = attr.getMechanismTypeSetValue();
			len += 8 + val.size() * 8;
		}
		else
		{
			return false;
		}
	}

	// write length
	if (!writeULong(len))
	{
		return false;
	}

	// write each attribute
	for (std::map<CK_ATTRIBUTE_TYPE,OSAttribute>::const_iterator i = value.begin(); i != value.end(); ++i)
	{
		OSAttribute attr = i->second;
		unsigned long attrType = (unsigned long) i->first;
		if (!writeULong(attrType))
		{
			return false;
		}

		if (attr.isBooleanAttribute())
		{
			unsigned long attrKind = akBoolean;
			if (!writeULong(attrKind))
			{
				return false;
			}

			bool val = attr.getBooleanValue();
			if (!writeBool(val))
			{
				return false;
			}
		}
		else if (attr.isUnsignedLongAttribute())
		{
			unsigned long attrKind = akInteger;
			if (!writeULong(attrKind))
			{
				return false;
			}

			unsigned long val = attr.getUnsignedLongValue();
			if (!writeULong(val))
			{
				return false;
			}
		}
		else if (attr.isByteStringAttribute())
		{
			unsigned long attrKind = akBinary;
			if (!writeULong(attrKind))
			{
				return false;
			}

			ByteString val = attr.getByteStringValue();
			if (!writeByteString(val))
			{
				return false;
			}
		}
		else if (attr.isMechanismTypeSetAttribute())
		{
			unsigned long attrKind = akMechSet;
			if (!writeULong(attrKind))
			{
				return false;
			}

			std::set<CK_MECHANISM_TYPE> val = attr.getMechanismTypeSetValue();
			if (!writeMechanismTypeSet(val))
			{
				return false;
			}
		}
	}

	flush();
		return true;
}

// Write a boolean value; warning: not thread safe without locking!
bool File::writeBool(const bool value)
{
	if (!valid) return false;

	unsigned char toWrite = value ? 0xFF : 0x00;

	// Write the value to the file
#ifdef SGXHSM
	if (sgx_fwrite(&toWrite, 1, 1, stream) != 1)
#else
	if (fwrite(&toWrite, 1, 1, stream) != 1)
#endif
	{
		return false;
	}

	flush();
		return true;
}

// Rewind the file
bool File::rewind()
{
	if (!valid) return false;

#ifdef SGXHSM
	sgx_fseek(stream, 0L, SEEK_SET);
#else
	::rewind(stream);
#endif
	return true;
}

// Truncate the file
bool File::truncate()
{
	if (!valid) return false;

#ifdef SGXHSM
	sgx_fclose(stream);
	valid = ((stream = sgx_fopen_auto_key(path.c_str(), "wb+")) != nullptr);

    while (!valid && ((EWOULDBLOCK == errno) || (EACCES == errno)))
    {
        sgx_fclose(stream);
        valid = ((stream = sgx_fopen_auto_key(path.c_str(), "wb+")) != nullptr);
    }

	return valid;
	#else

#ifndef _WIN32
	return (::ftruncate(fileno(stream), 0) == 0);
#else
	return (_chsize(_fileno(stream), 0) == 0);
#endif
#endif
}

// Seek to the specified position relative to the start of the file; if no
// argument is specified this operation seeks to the end of the file
bool File::seek(long offset /* = -1 */)
{
	if (offset == -1)
	{
#ifdef SGXHSM
		return valid && (valid = !sgx_fseek(stream, 0, SEEK_END));
#else
		return valid && (valid = !fseek(stream, 0, SEEK_END));
#endif
	}
	else
	{
#ifdef SGXHSM
		return valid && (valid = !sgx_fseek(stream, offset, SEEK_SET));
#else
		return valid && (valid = !fseek(stream, offset, SEEK_SET));
#endif
	}
}

// Lock the file
bool File::lock(bool block /* = true */)
{
#ifndef SGXHSM
#ifndef _WIN32
	struct flock fl;
	fl.l_type = isWrite() ? F_WRLCK : F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = 0;

	if (locked || !valid) return false;

	if (fcntl(fileno(stream), block ? F_SETLKW : F_SETLK, &fl) != 0)
	{
		// ERROR_MSG("Could not lock the file: %s", strerror(errno));
		return false;
	}
#else
	HANDLE hFile;
	DWORD flags = 0;
	OVERLAPPED o;

	if (isWrite()) flags |= LOCKFILE_EXCLUSIVE_LOCK;
	if (!block) flags |= LOCKFILE_FAIL_IMMEDIATELY;

	if (locked || !valid) return false;

	hFile = (HANDLE) _get_osfhandle(_fileno(stream));
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// ERROR_MSG("Invalid handle");
		return false;
	}

	memset(&o, 0, sizeof(o));
	if (!LockFileEx(hFile, flags, 0, 1, 0, &o))
	{
		DWORD rv = GetLastError();

		// ERROR_MSG("Could not lock the file: 0x%08x", rv);
		return false;
	}
#endif
#endif
	locked = true;

	return true;
}

// Unlock the file
bool File::unlock()
{

#ifndef SGXHSM
#ifndef _WIN32
	struct flock fl;
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = 0;

	if (!locked || !valid) return false;

	if (fcntl(fileno(stream), F_SETLK, &fl) != 0)
	{
		valid = false;

		// ERROR_MSG("Could not unlock the file: %s", strerror(errno));
		return false;
	}
#else
	HANDLE hFile;
	OVERLAPPED o;

	if (!locked || !valid) return false;

	hFile = (HANDLE) _get_osfhandle(_fileno(stream));
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// ERROR_MSG("Invalid handle");
		return false;
	}

	memset(&o, 0, sizeof(o));
	if (!UnlockFileEx(hFile, 0, 1, 0, &o))
	{
		DWORD rv = GetLastError();

		valid = false;

		// ERROR_MSG("Could not unlock the file: 0x%08x", rv);
		return  false;
	}
#endif
#endif	

	locked = false;

	return valid;
}

// Flush the buffered stream to background storage
bool File::flush()
{
#ifdef SGXHSM
	return valid && !sgx_fflush(stream);
#else
	return valid && !fflush(stream);
#endif
}

