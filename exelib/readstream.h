/// \file   ReadStream.h
/// Provides a helper function to read binary data from a stream
/// without having to have repeated reinterpret_casts scattered
/// throughout the code.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_READSTREAM_H_
#define _EXELIB_READSTREAM_H_

#include <istream>
#include <vector>

template<typename T>
size_t read(std::istream &stream, T &destination)
{
    stream.read(reinterpret_cast<char *>(&destination), sizeof(T));

    return sizeof(T);
}


inline std::string read_sz_string(std::istream &stream)
{
    std::string rv;
    char        ch;

    while (true)
    {
        read(stream, ch);
        if (ch == 0)
            break;
        rv.push_back(ch);
    }

    return rv;
}

inline std::string read_sz_string(std::istream &stream, unsigned alignment)
{
    std::string rv{read_sz_string(stream)};
    auto        len = rv.size();

    char ch;
    while ((len + 1) % alignment)
    {
        read(stream, ch);
        ++len;
    }

    return rv;
}

inline std::string read_string(std::istream &stream, uint32_t byte_count)
{
    std::string rv(byte_count, '\0');
    char        ch;

    for (uint32_t i = 0; i < byte_count; ++i)
    {
        read(stream, ch);
        rv[i] = ch;
    }

    return rv;
}

inline std::string read_length_and_string(std::istream &stream)
{
    uint32_t    byte_count;

    read(stream, byte_count);

    return read_string(stream, byte_count);
}


class BytesReader
{
public:
    BytesReader(const std::vector<uint8_t> &bytes)
      : _bytes{bytes}
    {}

    size_t tell() const noexcept
    {
        return _pos;
    }

    void seek(size_t pos) noexcept
    {
        _pos = pos;
    }

    size_t read(uint64_t &value)
    {
        value = (static_cast<uint64_t>(_bytes[_pos++]))
              | (static_cast<uint64_t>(_bytes[_pos++]) <<  8)
              | (static_cast<uint64_t>(_bytes[_pos++]) << 16)
              | (static_cast<uint64_t>(_bytes[_pos++]) << 24)
              | (static_cast<uint64_t>(_bytes[_pos++]) << 32)
              | (static_cast<uint64_t>(_bytes[_pos++]) << 40)
              | (static_cast<uint64_t>(_bytes[_pos++]) << 48)
              | (static_cast<uint64_t>(_bytes[_pos++]) << 56);

        return sizeof(value);
    }

    size_t read(uint32_t &value)
    {
        value = (static_cast<uint32_t>(_bytes[_pos++]))
              | (static_cast<uint32_t>(_bytes[_pos++]) <<  8)
              | (static_cast<uint32_t>(_bytes[_pos++]) << 16)
              | (static_cast<uint32_t>(_bytes[_pos++]) << 24);

        return sizeof(value);
    }

    size_t read(uint16_t &value)
    {
        value = (static_cast<uint16_t>(_bytes[_pos++]))
              | (static_cast<uint16_t>(_bytes[_pos++]) <<  8);

        return sizeof(value);
    }

    size_t read(uint8_t &value)
    {
        value = _bytes[_pos++];

        return sizeof(value);
    }

    size_t read(uint8_t *array, size_t count)
    {
        for (size_t i = 0; i < count; ++i)
            array[i] = _bytes[_pos++];

        return count;
    }

    size_t size() const noexcept
    {
        return _bytes.size();
    }

private:
    const std::vector<uint8_t> &_bytes;
    size_t                      _pos{0};
};

#endif  //_EXELIB_READSTREAM_H_
