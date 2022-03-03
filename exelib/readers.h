/// \file   readers.h
/// Provides helper functions as well as the BytesReader class for reading
/// binary data from an input stream and from a byte vector.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_READSTREAM_H_
#define _EXELIB_READSTREAM_H_

#include <istream>
#include <vector>
#include <utility>


/// \brief  Read binary data from an input stream into various primitive types.
/// \param stream       A reference to a std::istream from which to read bytes.
/// \param destination  A reference to a standard primitive type (\c char,
///                     \c uint32_t, etc.) in which to store the read bytes.
/// \return The number of bytes read from the stream.
///
/// \note   Conceivably this function could be used to read structures as well,
///         but there is no guarantee that the structure alignment in the stream
///         is the same as the structure in memory. Do this at your own risk.
template<typename T>
size_t read(std::istream &stream, T &destination)
{
    stream.read(reinterpret_cast<char *>(&destination), sizeof(T));

    return sizeof(T);
}

/// \brief  Read a nul-terminated ANSI string from an input stream.
/// \param stream   A reference to an std::istream from which to read the string.
/// \return An std::string containing the read string. The terminating nul
///         character is not stored in the returned string, so the total
///         number of bytes read will be one more than the \c size of the
///         returned string.
inline std::string read_sz_string(std::istream &stream)
{
    std::string rv;
    char        ch{};

    while (true)
    {
        read(stream, ch);
        if (ch == 0)
            break;
        rv.push_back(ch);
    }

    return rv;
}

/// \brief  Read a nul-terminated ANSI string from an input stream, reading and
///         discarding subsequent bytes until the alignment is reached.
/// \param stream       A reference to an std::istream from which to read the string.
/// \param alignment    The alignment value.
/// \return An std::string object containing the read characters.
///
/// If an aligned nul-terminated string contains nine characters plus the nul,
/// with an aignment value of four, the function will read the nine characters
/// and the terminating null, then two additional bytes to reach twelve,
/// the next multiple of four. The nul characters and alignment bytes are not
/// stored in the returned string.
inline std::string read_sz_string(std::istream &stream, unsigned alignment)
{
    std::string rv{read_sz_string(stream)};
    auto        len{rv.size()};
    char        ch{};

    while ((len + 1) % alignment)
    {
        read(stream, ch);
        ++len;
    }

    return rv;
}

/// \brief  Read a string of a specified number of bytes from an input stream.
/// \param stream       A reference to an std::istream from which to read the string.
/// \param byte_count   The number of bytes to read to produce the string.
/// \return An std::string object containing the read characters.
inline std::string read_string(std::istream &stream, uint32_t byte_count)
{
    std::string rv(byte_count, '\0');
    char        ch{};

    for (uint32_t i = 0; i < byte_count; ++i)
    {
        read(stream, ch);
        rv.at(i) = ch;
    }

    return rv;
}

/// \brief  Read a string that is preceded by a length from an input stream.
///         The length is assumed to be a 32-bit unsigned integer.
/// \param stream   A reference to an std::istream from which to read the string.
/// \return An std::string object containing the read characters.
inline std::pair<uint32_t, std::string> read_length_and_string(std::istream &stream)
{
    uint32_t    byte_count;

    read(stream, byte_count);

    return {byte_count, read_string(stream, byte_count)};
}


/// \brief  A class for reading from an std::vector<uint8_t> byte "stream".
///         The class maintains the current index into the vector.
///
/// \note   The class does not make a copy of the vector, rather it maintains
///         a refererce to the vector given to the constructor.
class BytesReader
{
public:
    BytesReader(const std::vector<uint8_t> &bytes) noexcept
      : _bytes{bytes}
    {}

    BytesReader(const BytesReader &) = delete;              // The copy constructor is deleted
    BytesReader(BytesReader &&) = delete;                   // The move constructor is deleted
    BytesReader &operator=(const BytesReader &) = delete;   // The copy assignment operator is deleted
    BytesReader &operator=(BytesReader &&) = delete;        // The move assignment operator is deleted

    /// \brief  Return the current index position.
    size_t tell() const noexcept
    {
        return _pos;
    }

    /// \brief  Move the index position to the specified absolute location.
    ///
    /// \note   The index position is adjusted even if the position is beyond
    ///         the boundaries of the vector. No checking is performed in this
    ///         function. Subsequent attempts to read after positioning outside
    ///         the boundaries of the vector will result in an exception being
    ///         thrown by the standard library.
    void seek(size_t pos) noexcept
    {
        _pos = pos;
    }

    /// \brief  Read a 64-bit unsigned value from the byte vector.
    /// \param value    A reference to a 64-bit unsigned integer in which to
    ///                 store the read bytes.
    /// \return The number of bytes read.
    size_t read(uint64_t &value)
    {
        value = (static_cast<uint64_t>(_bytes.at(_pos++)))
              | (static_cast<uint64_t>(_bytes.at(_pos++)) <<  8)
              | (static_cast<uint64_t>(_bytes.at(_pos++)) << 16)
              | (static_cast<uint64_t>(_bytes.at(_pos++)) << 24)
              | (static_cast<uint64_t>(_bytes.at(_pos++)) << 32)
              | (static_cast<uint64_t>(_bytes.at(_pos++)) << 40)
              | (static_cast<uint64_t>(_bytes.at(_pos++)) << 48)
              | (static_cast<uint64_t>(_bytes.at(_pos++)) << 56);

        return sizeof(value);
    }

    /// \brief  Read a 32-bit unsigned value from the byte vector.
    /// \param value    A reference to a 32-bit unsigned integer in which to
    ///                 store the read bytes.
    /// \return The number of bytes read.
    size_t read(uint32_t &value)
    {
        value = (static_cast<uint32_t>(_bytes.at(_pos++)))
              | (static_cast<uint32_t>(_bytes.at(_pos++)) <<  8)
              | (static_cast<uint32_t>(_bytes.at(_pos++)) << 16)
              | (static_cast<uint32_t>(_bytes.at(_pos++)) << 24);

        return sizeof(value);
    }

    /// \brief  Read a 16-bit unsigned value from the byte vector.
    /// \param value    A reference to a 16-bit unsigned integer in which to
    ///                 store the read bytes.
    /// \return The number of bytes read.
    size_t read(uint16_t &value)
    {
        value = static_cast<uint16_t>((static_cast<uint16_t>(_bytes.at(_pos++)))
                                    | (static_cast<uint16_t>(_bytes.at(_pos++)) <<  8));

        return sizeof(value);
    }

    /// \brief  Read a single byte from the byte vector.
    /// \param value    A reference to a 8-bit unsigned integer in which to
    ///                 store the read byte.
    /// \return The number of bytes read.
    size_t read(uint8_t &value)
    {
        value = _bytes.at(_pos++);

        return sizeof(value);
    }

    /// \brief  Read a given number of bytes into an array.
    /// \param array    A pointer to an array of bytes. This must point to
    ///                 a location sufficiently large to contain the number
    ///                 of bytes specified in \p count.
    /// \param count    The number of bytes to be read.
    size_t read(uint8_t *array, size_t count)
    {
        for (size_t i = 0; i < count; ++i)
            array[i] = _bytes.at(_pos++);

        return count;
    }

    /// \brief  Return the size of the underlying vector of bytes.
    size_t size() const noexcept
    {
        return _bytes.size();
    }

private:
    const std::vector<uint8_t> &_bytes;     // A reference to the given vector of bytes.
    size_t                      _pos{0};    // The current position within the vector.
};

#endif  //_EXELIB_READSTREAM_H_
