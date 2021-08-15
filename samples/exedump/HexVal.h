/// \file   ExeInfo.h
/// Class and insertion function for formatting hex values inserted into an ostreams.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_HEXVAL_H_
#define _EXELIB_HEXVAL_H_

#include <iomanip>
#include <iosfwd>

namespace {
// Helper class to write a hex value to an output stream using io manipulators.
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

}   // anonymous namespace


#endif  // _EXELIB_HEXVAL_H_
