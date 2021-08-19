/// \file   ExeInfo.h
/// Classses for writing hex data to a stream.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_HEXVAL_H_
#define _EXELIB_HEXVAL_H_

#include <cstdint>
#include <cctype>
#include <iomanip>
#include <iosfwd>

// Helper class to write a hex value to an output stream using stream manipulators.
template <typename T>
class HexVal final
{
public:
    T               value;
    std::streamsize output_width;
    char            fill_char;

    HexVal(T value, std::streamsize width = sizeof(T) * 2, char fill_char = '0')
        : value{value}
        , output_width{width}
        , fill_char{fill_char}
    { }
};

template <typename T>
inline std::ostream &operator<<(std::ostream &os, const HexVal<T> &value)
{
    auto current_fill = os.fill(value.fill_char);
    auto current_flags = os.flags();

    os << std::hex << std::uppercase << std::setw(value.output_width) << (sizeof(T) == 1 ? static_cast<uint16_t>(value.value) : value.value);

    os.fill(current_fill);
    os.flags(current_flags);

    return os;
}

template <typename T>
struct BasicHexDump
{
    BasicHexDump(const uint8_t *data, size_t length, T start=static_cast<T>(0))
        : data{data}
        , length{length}
        , start_address{start}
    {};

    const uint8_t  *data;
    const size_t    length;
    const T         start_address;
};

template<typename T>
std::ostream &operator<<(std::ostream &outstream, const BasicHexDump<T> &dump)
{
    constexpr auto addr_width{sizeof(T) * 2};
    constexpr auto row_length{16u};

    T addr = dump.start_address;

    auto old_fill = outstream.fill('0');
    auto old_flags = outstream.flags(std::ios::uppercase | std::ios::hex);

    for (size_t r = 0; r < dump.length; r += row_length, addr += row_length)
    {
        outstream << std::setw(addr_width) << addr << ": ";

        for (unsigned c = 0; c < row_length; ++c)
        {
            if (r + c < dump.length)
                outstream << std::setw(2) << static_cast<unsigned>(dump.data[r + c]) << ' ';
            else
                outstream << "   ";
        }

        for (size_t c = 0; c < row_length; ++c)
        {
            if (r + c < dump.length)
            {
                if (std::isprint(dump.data[r + c]))
                    outstream << static_cast<char>(dump.data[r + c]);
                else
                    outstream << '.';
            }
        }
        outstream << '\n';
    }

    outstream.setf(old_flags);
    outstream.fill(old_fill);

    return outstream;
}
using HexDump = BasicHexDump<uint32_t>;
using VaHexDump = BasicHexDump<uint64_t>;

#endif  // _EXELIB_HEXVAL_H_
