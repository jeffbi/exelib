/// \file   PEExe.cpp
/// Implementation of CLI-specific classes.
///
/// \author Jeff Bienstadt
///

#include <exception>
#include <istream>
#include <string>
#include <vector>

#include "LoadOptions.h"
#include "PEExe.h"
#include "readers.h"

namespace {
// calculate the length of an entry in a #US or #Blob CLI metadata stream
uint32_t get_blob_length(const std::vector<uint8_t> &bytes, size_t &bytes_read)
{
    uint32_t    len{0};
    uint8_t     c1{bytes[bytes_read++]};

    if ((c1 & 0b11100000) == 0b11000000)
    {
        // need four bytes for the length
        uint8_t c2 = bytes[bytes_read++];
        uint8_t c3 = bytes[bytes_read++];
        uint8_t c4 = bytes[bytes_read++];

        len =    ((static_cast<uint32_t>(c1) & 0b00011111) << 24)
                | (static_cast<uint32_t>(c2) << 16)
                | (static_cast<uint32_t>(c3) << 8)
                | (static_cast<uint32_t>(c4));

    }
    else if ((c1 & 0b11000000) == 0b10000000)
    {
        // need two bytes for the length
        uint8_t c2 = bytes[bytes_read++];

        len = ((static_cast<uint32_t>(c1) & 0b00111111) << 8) | static_cast<uint32_t>(c2);
    }
    else if ((c1 & 0b10000000) == 0b00000000)
    {
        // one byte does it
        len = c1;
    }
    else
    {
        // should never get here!!!
        throw std::runtime_error("Length in #US stream is invalid.");
    }

    return len;
}

template<typename T>
inline int count_set_bits(T value)
{
    int rv{0};

    for (T i = 0; i < sizeof(T) * 8; ++i)
        if (value & (static_cast<T>(1) << i))
            ++rv;

    return rv;
}

template<typename T>
inline bool is_bit_set(T value, int bit_number)
{
    return value & (static_cast<T>(1) << bit_number);
}

}   // end of anonymous namespace


void PeCliMetadata::load(std::istream &stream, LoadOptions::Options options)
{
    auto    metadata_header_pos{stream.tellg()};

    _metadata_header = std::make_unique<PeCliMetadataHeader>();
    read(stream, _metadata_header->signature);
    read(stream, _metadata_header->major_version);
    read(stream, _metadata_header->minor_version);
    read(stream, _metadata_header->reserved);
    _metadata_header->version = read_length_and_string(stream);
    read(stream, _metadata_header->flags);
    read(stream, _metadata_header->stream_count);

    // Load the metadata stream information
    _stream_headers.reserve(_metadata_header->stream_count);
    for (uint16_t i = 0; i < _metadata_header->stream_count; ++i)
    {
        PeCliStreamHeader   header;

        read(stream, header.offset);
        read(stream, header.size);
        header.name = read_sz_string(stream, 4);    // stream names are zero-padded to 4 byte multiples

        _stream_headers.push_back(header);
    }

    if (options | LoadOptions::LoadCliMetadataStreams)
    {
        // Load the metadata streams.
        // There are member functions to interpret the #Strings, #US, #GUID, and #~ streams.
        _streams.reserve(_metadata_header->stream_count);
        for (uint16_t i = 0; i < _metadata_header->stream_count; ++i)
        {
            std::vector<uint8_t>    stream_bytes(_stream_headers[i].size);

            stream.seekg(metadata_header_pos + static_cast<std::streamoff>(_stream_headers[i].offset));
            stream.read(reinterpret_cast<char *>(&stream_bytes[0]), _stream_headers[i].size);

            _streams.push_back(std::move(stream_bytes));
        }

        if (options | LoadOptions::LoadCliMetadataTables)
            load_metadata_tables();
    }
}


std::vector<std::string> PeCliMetadata::get_strings_heap_strings() const
{
    std::vector<std::string>    rv;
    const auto                 &bytes{get_stream("#Strings")};

    if (bytes.size())
    {
        size_t  bytes_read{0};

        // ignore the first byte
        ++bytes_read;

        std::string str;
        while (bytes_read < bytes.size())
        {
            auto    ch = static_cast<char>(bytes[bytes_read++]);

            if (ch == '\0')
            {
                rv.push_back(std::move(str));
                str.erase();
            }
            else
            {
                str.push_back(ch);
            }
        }
    }

    return rv;
}

std::vector<std::u16string> PeCliMetadata::get_us_heap_strings() const
{
    std::vector<std::u16string> rv;
    const auto                 &bytes{get_stream("#US")};

    if (bytes.size())
    {
        size_t          bytes_read{0};
        std::u16string  str;

        while (bytes_read < bytes.size())
        {
            uint32_t    len{get_blob_length(bytes, bytes_read)};
            char16_t    ch;

            // read len bytes
            for (uint32_t i = 0; i < len; ++i)
            {
                if ((i & 0x01) == 0)    // either the start of a UTF-16 character, or the ending byte
                {
                    if (i == len-1)
                    {
                        // at the last byte, ignore it
                        ++bytes_read;
                        //TODO: This byte should not be ignored. It has meaning, but I haven't decided what to do about it yet.
                        //      From ECMA-335, 6th edition:
                        //          This final byte holds the value 1 if and only if any UTF16 character within the string
                        //          has any bit set in its top byte, or its low byte is any of the following: 0x01–0x08,
                        //          0x0E–0x1F, 0x27, 0x2D, 0x7F. Otherwise, it holds 0. The 1 signifies Unicode characters
                        //          that require handling beyond that normally provided for 8-bit encoding sets.
                    }
                    else
                    {
                        // read the first byte of the character
                        ch = static_cast<char16_t>(bytes[bytes_read++]);
                    }
                }
                else
                {
                    // read the second byte of the character
                    ch |= (static_cast<char16_t>(bytes[bytes_read++])) << 8;
                    str.push_back(ch);
                }
            }

            rv.push_back(std::move(str));
        }
    }

    return rv;
}

std::vector<std::vector<uint8_t>> PeCliMetadata::get_blob_heap_blobs() const
{
    std::vector<std::vector<uint8_t>>   rv;
    const auto                         &bytes{get_stream("#Blob")};

    if (bytes.size())
    {
        size_t                  bytes_read{0};
        std::vector<uint8_t>    vec;

        while (bytes_read < bytes.size())
        {
            uint32_t    len{get_blob_length(bytes, bytes_read)};

            vec.reserve(len);

            // read len bytes
            for (uint32_t i = 0; i < len; ++i)
            {
                // read and store the byte
                vec.push_back(bytes[bytes_read++]);
            }

            rv.push_back(std::move(vec));
        }
    }

    return rv;
}

std::vector<Guid> PeCliMetadata::get_guid_heap_guids() const
{
    BytesReader         reader{get_stream("#GUID")};
    size_t              num_guids{reader.size() / sizeof(Guid)};
    std::vector<Guid>   rv;

    rv.reserve(num_guids);
    for (size_t i = 0; i < num_guids; ++i)
    {
        Guid    guid;

        reader.read(guid.data1);
        reader.read(guid.data2);
        reader.read(guid.data3);
        reader.read(guid.data4, sizeof(guid.data4));

        rv.push_back(guid);
    }

    return rv;
}

void PeCliMetadata::load_metadata_tables()
{
    if (!_tables)
    {
        BytesReader reader{get_stream("#~")};

        if (reader.size())
        {
            _tables = std::make_unique<PeCliMetadataTables>();
            _tables->load(reader);
        }
    }
}

PeCliMetadataTableIndex PeCliMetadata::decode_index(PeCliEncodedIndexType type, uint32_t index) const
{
    PeCliMetadataTableIndex rv;

    switch (type)
    {
        case PeCliEncodedIndexType::TypeDefOrRef:           // 2 bits to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::TypeDef,
                                                            PeCliMetadataTableId::TypeRef,
                                                            PeCliMetadataTableId::TypeSpec
                                                        };

                if ((index & 0b11) > 2)
                    throw std::runtime_error("Invalid table type value encoded into 'TypeDefOrRef' index.");
                rv.table_id = ids[index & 0b11];
                rv.index = index >> 2;
            }
            break;
        case PeCliEncodedIndexType::HasConstant:            // 2 bits to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::Field,
                                                            PeCliMetadataTableId::Param,
                                                            PeCliMetadataTableId::Property
                                                        };
                if ((index & 0b11) > 2)
                    throw std::runtime_error("Invalid table type value encoded into 'HasConstant' index.");
                rv.table_id = ids[index & 0b11];
                rv.index = index >> 2;
            }
            break;
        case PeCliEncodedIndexType::HasCustomAttribute:     // 5 bits to decode tag
            {
                uint32_t    ndx = (index & 0b11111);

                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::MethodDef,
                                                            PeCliMetadataTableId::Field,
                                                            PeCliMetadataTableId::TypeRef,
                                                            PeCliMetadataTableId::TypeDef,
                                                            PeCliMetadataTableId::Param,
                                                            PeCliMetadataTableId::InterfaceImpl,
                                                            PeCliMetadataTableId::MemberRef,
                                                            PeCliMetadataTableId::Module,
                                                            PeCliMetadataTableId::Module,   //!!! Just a placeholder! We will never index this element of the array!
                                                            PeCliMetadataTableId::Property,
                                                            PeCliMetadataTableId::Event,
                                                            PeCliMetadataTableId::StandAloneSig,
                                                            PeCliMetadataTableId::ModuleRef,
                                                            PeCliMetadataTableId::TypeSpec,
                                                            PeCliMetadataTableId::Assembly,
                                                            PeCliMetadataTableId::AssemblyRef,
                                                            PeCliMetadataTableId::File,
                                                            PeCliMetadataTableId::ExportedType,
                                                            PeCliMetadataTableId::ManifestResource,
                                                            PeCliMetadataTableId::GenericParam,
                                                            PeCliMetadataTableId::GenericParamConstraint,
                                                            PeCliMetadataTableId::MethodSpec
                                                        };
                // ECMA-335 specifies 22 tables encoded into this type of index.
                // However it includes number 8 as a "Permission" table, which
                // does not exist anywhere else in the spec. For now it is a error.
                if (ndx > 21 || ndx == 8)
                    throw std::runtime_error("Invalid table type value encoded into 'HasCustomAttribute' index.");
                rv.table_id = ids[ndx];
                rv.index = index >> 5;
            }
            break;
        case PeCliEncodedIndexType::HasFieldMarshall:       // 1 bit to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::Field,
                                                            PeCliMetadataTableId::Param
                                                        };
                rv.table_id = ids[index & 0b1];
                rv.index = index >> 1;
            }
            break;
        case PeCliEncodedIndexType::HasDeclSecurity:        // 2 bits to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::TypeDef,
                                                            PeCliMetadataTableId::MethodDef,
                                                            PeCliMetadataTableId::Assembly
                                                        };
                if ((index & 0b11) > 2)
                    throw std::runtime_error("Invalid table type value encoded into 'HasDeclSecurity' index.");
                rv.table_id = ids[index & 0b11];
                rv.index = index >> 2;
            }
            break;
        case PeCliEncodedIndexType::MemberRefParent:        // 3 bits to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::TypeDef,
                                                            PeCliMetadataTableId::TypeRef,
                                                            PeCliMetadataTableId::ModuleRef,
                                                            PeCliMetadataTableId::MethodDef,
                                                            PeCliMetadataTableId::TypeSpec
                                                        };
                if ((index & 0b111) > 4)
                    throw std::runtime_error("Invalid table type value encoded into 'MemberRefParent' index.");
                rv.table_id = ids[index & 0b111];
                rv.index = index >> 3;
            }
            break;
        case PeCliEncodedIndexType::HasSemantics:           // 1 bit to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::Event,
                                                            PeCliMetadataTableId::Property
                                                        };
                rv.table_id = ids[index & 0b1];
                rv.index = index >> 1;
            }
            break;
        case PeCliEncodedIndexType::MethodDefOrRef:         // 1 bit to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::MethodDef,
                                                            PeCliMetadataTableId::MemberRef
                                                        };
                rv.table_id = ids[index & 0b1];
                rv.index = index >> 1;
            }
            break;
        case PeCliEncodedIndexType::MemberForwarded:        // 1 bit to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::Field,
                                                            PeCliMetadataTableId::MethodDef
                                                        };
                rv.table_id = ids[index & 0b1];
                rv.index = index >> 1;
            }
            break;
        case PeCliEncodedIndexType::Implementation:         // 2 bits to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::File,
                                                            PeCliMetadataTableId::AssemblyRef,
                                                            PeCliMetadataTableId::ExportedType
                                                        };
                if ((index & 0b11) > 2)
                    throw std::runtime_error("Invalid table type value encoded into 'Implementation' index.");
                rv.table_id = ids[index & 0b11];
                rv.index = index >> 2;
            }
            break;
        case PeCliEncodedIndexType::CustomAttributeType:    // 3 bits to decode tag
            {
                switch (index & 0b111)
                {
                    case 0:     // In the spec as unused
                    case 1:     // In the spec as unused
                    case 4:     // In the spec as unused
                    default:
                        throw std::runtime_error("Invalid table type value encoded into 'CustomAttributeType' index.");
                        break;
                    case 2:
                        rv.table_id = PeCliMetadataTableId::MethodDef;
                        break;
                    case 3:
                        rv.table_id = PeCliMetadataTableId::MemberRef;
                        break;
                };
                rv.index = index >> 3;
            }
            break;
        case PeCliEncodedIndexType::ResolutionScope:        // 2 bits to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::Module,
                                                            PeCliMetadataTableId::ModuleRef,
                                                            PeCliMetadataTableId::AssemblyRef,
                                                            PeCliMetadataTableId::TypeRef
                                                        };
                rv.table_id = ids[index & 0b11];
                rv.index = index >> 2;
            }
            break;
        case PeCliEncodedIndexType::TypeOrMethodDef:        // 1 bit to decode tag
            {
                constexpr PeCliMetadataTableId ids[] =  {
                                                            PeCliMetadataTableId::TypeDef,
                                                            PeCliMetadataTableId::MethodDef
                                                        };
                rv.table_id = ids[index & 0b1];
                rv.index = index >> 1;
            }
            break;
        default:
            throw std::runtime_error("Unrecognized encoded index type");    // This should never happen
    };

    return rv;
}

void PeCliMetadataTables::load(BytesReader &reader)
{
    reader.read(_header.reserved0);
    reader.read(_header.major_version);
    reader.read(_header.minor_version);
    reader.read(_header.heap_sizes);
    reader.read(_header.reserved1);
    reader.read(_header.valid_tables);
    reader.read(_header.sorted_tables);

    int nValid{count_set_bits(_header.valid_tables)};
    int nSorted{count_set_bits(_header.sorted_tables)};

    _valid_table_types.reserve(nValid);
    for (int i = 0; i < 64; ++i)
        if (is_bit_set(_header.valid_tables, i))
            _valid_table_types.push_back(static_cast<PeCliMetadataTableId>(i));

    _header.row_counts.reserve(nValid);
    for (int i = 0; i < nValid; ++i)
    {
        uint32_t    row;
        reader.read(row);
        _header.row_counts.push_back(row);
    }

    auto    needs_wide_index = [this](PeCliMetadataTableId id)
            {
                constexpr uint32_t  threshold{65535};

                for (int i = 0; i < this->_valid_table_types.size(); ++i)
                    if (this->_valid_table_types[i] == id)
                        if (this->_header.row_counts[i] > threshold)
                            return true;

                return false;
            };
    auto    needs_wide_index_vec = [this, &needs_wide_index](const std::vector<PeCliMetadataTableId> &ids)
            {
                //TODO: Not completely sure this is correct! Take a closer look at page 274 of the ECMA-335 spec.
                for (auto id : ids)
                    if (needs_wide_index(id))
                        return true;

                return false;
            };

    // Following the header and the row counts are the tables themselves.
    for (int i = 0; i < _valid_table_types.size(); ++i)
    {
        uint32_t    row_count{_header.row_counts[i]};

        switch (_valid_table_types[i])
        {
            case PeCliMetadataTableId::Assembly:
                _assembly_table = std::make_unique<std::vector<PeCliMetadataRowAssembly>>();
                _assembly_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowAssembly    row;
                    reader.read(row.hash_alg_id);
                    reader.read(row.major_version);
                    reader.read(row.minor_version);
                    reader.read(row.build_number);
                    reader.read(row.revision_number);
                    reader.read(row.flags);
                    read_blob_heap_index(reader, row.public_key);
                    read_strings_heap_index(reader, row.name);
                    read_strings_heap_index(reader, row.culture);

                    _assembly_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::AssemblyOS:
                _assembly_os_table = std::make_unique<std::vector<PeCliMetadataRowAssemblyOS>>();
                _assembly_os_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowAssemblyOS  row;
                    reader.read(row.os_platformID);
                    reader.read(row.os_major_version);
                    reader.read(row.os_minor_version);

                    _assembly_os_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::AssemblyProcessor:
                _assembly_processor = std::make_unique<std::vector<PeCliMetadataRowAssemblyProcessor>>();
                _assembly_processor->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowAssemblyProcessor   row;
                    reader.read(row.processor);

                    _assembly_processor->push_back(row);
                }
                break;
            case PeCliMetadataTableId::AssemblyRef:
                _assembly_ref_table = std::make_unique<std::vector<PeCliMetadataRowAssemblyRef>>();
                _assembly_ref_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowAssemblyRef row;
                    reader.read(row.major_version);
                    reader.read(row.minor_version);
                    reader.read(row.build_number);
                    reader.read(row.revision_number);
                    reader.read(row.flags);
                    read_blob_heap_index(reader, row.public_key_or_token);
                    read_strings_heap_index(reader, row.name);
                    read_strings_heap_index(reader, row.culture);
                    read_blob_heap_index(reader, row.hash_value);

                    _assembly_ref_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::AssemblyRefOS:
                _assembly_ref_os_table = std::make_unique<std::vector<PeCliMetadataRowAssemblyRefOS>>();
                _assembly_ref_os_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowAssemblyRefOS   row;
                    reader.read(row.os_platformID);
                    reader.read(row.os_major_version);
                    reader.read(row.os_minor_version);
                    read_index(reader, row.assembly_ref, needs_wide_index(PeCliMetadataTableId::AssemblyRefOS));

                    _assembly_ref_os_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::AssemblyRefProcessor:
                _assembly_ref_processor_table = std::make_unique<std::vector<PeCliMetadataRowAssemblyRefProcessor>>();
                _assembly_ref_processor_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowAssemblyRefProcessor    row;
                    reader.read(row.processor);
                    read_index(reader, row.assembly_ref, needs_wide_index(PeCliMetadataTableId::AssemblyRefProcessor));

                    _assembly_ref_processor_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::ClassLayout:
                _class_layout_table = std::make_unique<std::vector<PeCliMetadataRowClassLayout>>();
                _class_layout_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowClassLayout row;
                    reader.read(row.packing_size);
                    reader.read(row.class_size);
                    read_index(reader, row.parent, needs_wide_index(PeCliMetadataTableId::ClassLayout));

                    _class_layout_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::Constant:
                _constant_table = std::make_unique<std::vector<PeCliMetadataRowConstant>>();
                _constant_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowConstant    row;
                    reader.read(row.type);
                    reader.read(row.padding);

                    read_index(reader, row.parent, needs_wide_index_vec({PeCliMetadataTableId::Param, PeCliMetadataTableId::Field, PeCliMetadataTableId::Property}));

                    read_blob_heap_index(reader, row.value);

                    _constant_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::CustomAttribute:
                _custom_attribute_table = std::make_unique<std::vector<PeCliMetadataRowCustomAttribute>>();
                _custom_attribute_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowCustomAttribute row;
                    read_index(reader, row.parent, needs_wide_index_vec({PeCliMetadataTableId::MethodDef,
                                                                         PeCliMetadataTableId::Field,
                                                                         PeCliMetadataTableId::TypeRef,
                                                                         PeCliMetadataTableId::TypeDef,
                                                                         PeCliMetadataTableId::Param,
                                                                         PeCliMetadataTableId::InterfaceImpl,
                                                                         PeCliMetadataTableId::MemberRef,
                                                                         PeCliMetadataTableId::Module,
                                                                         //PeCliMetadataTableId::Permission,    // page 274 of the ECMA-355 document *appears* to say that this is a table, but there is no other reference to it as a table.
                                                                         PeCliMetadataTableId::Property,
                                                                         PeCliMetadataTableId::Event,
                                                                         PeCliMetadataTableId::StandAloneSig,
                                                                         PeCliMetadataTableId::ModuleRef,
                                                                         PeCliMetadataTableId::TypeSpec,
                                                                         PeCliMetadataTableId::Assembly,
                                                                         PeCliMetadataTableId::AssemblyRef,
                                                                         PeCliMetadataTableId::File,
                                                                         PeCliMetadataTableId::ExportedType,
                                                                         PeCliMetadataTableId::ManifestResource,
                                                                         PeCliMetadataTableId::GenericParam,
                                                                         PeCliMetadataTableId::GenericParamConstraint,
                                                                         PeCliMetadataTableId::MethodSpec}));
                    read_index(reader, row.type, needs_wide_index_vec({PeCliMetadataTableId::MethodDef, PeCliMetadataTableId::MemberRef}));
                    read_blob_heap_index(reader, row.value);

                    _custom_attribute_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::DeclSecurity:
                _decl_security_table = std::make_unique<std::vector<PeCliMetadataRowDeclSecurity>>();
                _decl_security_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowDeclSecurity    row;
                    reader.read(row.action);
                    read_index(reader, row.parent, needs_wide_index_vec({PeCliMetadataTableId::TypeDef, PeCliMetadataTableId::MethodDef, PeCliMetadataTableId::Assembly}));
                    read_blob_heap_index(reader, row.permission_set);

                    _decl_security_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::Event:
                _event_table = std::make_unique<std::vector<PeCliMetadataRowEvent>>();
                _event_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowEvent   row;
                    reader.read(row.event_flags);
                    read_strings_heap_index(reader, row.name);
                    read_index(reader, row.event_type, needs_wide_index_vec({PeCliMetadataTableId::TypeDef, PeCliMetadataTableId::TypeRef, PeCliMetadataTableId::TypeSpec}));

                    _event_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::EventMap:
                _event_map_table = std::make_unique<std::vector<PeCliMetadataRowEventMap>>();
                _event_map_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowEventMap  row;
                    read_index(reader, row.parent, needs_wide_index(PeCliMetadataTableId::TypeDef));
                    read_index(reader, row.event_list, needs_wide_index(PeCliMetadataTableId::Event));

                    _event_map_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::ExportedType:
                _exported_type_table = std::make_unique<std::vector<PeCliMetadataRowExportedType>>();
                _exported_type_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowExportedType    row;
                    reader.read(row.flags);
                    reader.read(row.typedef_id);    // This is an index, but it is always 4 bytes in size.
                    read_strings_heap_index(reader, row.type_name);
                    read_strings_heap_index(reader, row.type_namespace);
                    read_index(reader, row.implementation, needs_wide_index_vec({PeCliMetadataTableId::File, PeCliMetadataTableId::ExportedType, PeCliMetadataTableId::AssemblyRef}));

                    _exported_type_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::Field:
                _field_table = std::make_unique<std::vector<PeCliMetadataRowField>>();
                _field_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowField   row;
                    reader.read(row.flags);
                    read_strings_heap_index(reader, row.name);
                    read_blob_heap_index(reader, row.signature);

                    _field_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::FieldLayout:
                _field_layout_table = std::make_unique<std::vector<PeCliMetadataRowFieldLayout>>();
                _field_layout_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowFieldLayout row;
                    reader.read(row.offset);
                    read_index(reader, row.field, needs_wide_index(PeCliMetadataTableId::Field));

                    _field_layout_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::FieldMarshal:
                _field_marshal_table = std::make_unique<std::vector<PeCliMetadataRowFieldMarshal>>();
                _field_marshal_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowFieldMarshal    row;
                    read_index(reader, row.parent, needs_wide_index_vec({PeCliMetadataTableId::Field, PeCliMetadataTableId::Param}));
                    read_blob_heap_index(reader, row.native_type);

                    _field_marshal_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::FieldRVA:
                _field_rva_table = std::make_unique<std::vector<PeCliMetadataRowFieldRVA>>();
                _field_rva_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowFieldRVA    row;
                    reader.read(row.rva);
                    read_index(reader, row.field, needs_wide_index(PeCliMetadataTableId::Field));

                    _field_rva_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::File:
                _file_table = std::make_unique<std::vector<PeCliMetadataRowFile>>();
                _file_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowFile    row;
                    reader.read(row.flags);
                    read_strings_heap_index(reader, row.name);
                    read_blob_heap_index(reader, row.hash_value);

                    _file_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::GenericParam:
                _generic_param_table = std::make_unique<std::vector<PeCliMetadataRowGenericParam>>();
                _generic_param_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowGenericParam    row;
                    reader.read(row.number);
                    reader.read(row.flags);
                    read_index(reader, row.owner, needs_wide_index_vec({PeCliMetadataTableId::TypeDef, PeCliMetadataTableId::MethodDef}));
                    read_strings_heap_index(reader, row.name);

                    _generic_param_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::GenericParamConstraint:
                _generic_param_constraint_table = std::make_unique<std::vector<PeCliMetadataRowGenericParamConstraint>>();
                _generic_param_constraint_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowGenericParamConstraint  row;
                    read_index(reader, row.owner, needs_wide_index(PeCliMetadataTableId::GenericParam));
                    read_index(reader, row.constraint, needs_wide_index_vec({PeCliMetadataTableId::TypeDef, PeCliMetadataTableId::TypeRef, PeCliMetadataTableId::TypeSpec}));

                    _generic_param_constraint_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::ImplMap:
                _impl_map_table = std::make_unique<std::vector<PeCliMetadataRowImplMap>>();
                _impl_map_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowImplMap row;
                    reader.read(row.mapping_flags);
                    read_index(reader, row.member_forwarded, needs_wide_index_vec({PeCliMetadataTableId::Field, PeCliMetadataTableId::MethodDef}));
                    read_strings_heap_index(reader, row.import_name);
                    read_index(reader, row.import_scope, needs_wide_index(PeCliMetadataTableId::ModuleRef));


                    _impl_map_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::InterfaceImpl:
                _interface_impl_table = std::make_unique<std::vector<PeCliMetadataRowInterfaceImpl>>();
                _interface_impl_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowInterfaceImpl   row;
                    read_index(reader, row.class_, needs_wide_index(PeCliMetadataTableId::TypeDef));
                    read_index(reader, row.interface, needs_wide_index_vec({PeCliMetadataTableId::TypeDef, PeCliMetadataTableId::TypeRef, PeCliMetadataTableId::TypeSpec}));

                    _interface_impl_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::ManifestResource:
                _manifest_resource_table = std::make_unique<std::vector<PeCliMetadataRowManifestResource>>();
                _manifest_resource_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowManifestResource  row;
                    reader.read(row.offset);
                    reader.read(row.flags);
                    read_strings_heap_index(reader, row.name);
                    read_index(reader, row.implementation, needs_wide_index_vec({PeCliMetadataTableId::File, PeCliMetadataTableId::AssemblyRef}));

                    _manifest_resource_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::MemberRef:
                _member_ref_table = std::make_unique<std::vector<PeCliMetadataRowMemberRef>>();
                _member_ref_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowMemberRef   row;
                    read_index(reader, row.class_, needs_wide_index_vec({PeCliMetadataTableId::MethodDef, PeCliMetadataTableId::ModuleRef, PeCliMetadataTableId::TypeDef, PeCliMetadataTableId::TypeRef, PeCliMetadataTableId::TypeSpec}));
                    read_strings_heap_index(reader, row.name);
                    read_blob_heap_index(reader, row.signature);

                    _member_ref_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::MethodDef:
                _method_def_table = std::make_unique<std::vector<PeCliMetadataRowMethodDef>>();
                _method_def_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowMethodDef   row;
                    reader.read(row.rva);
                    reader.read(row.impl_flags);
                    reader.read(row.flags);
                    read_strings_heap_index(reader, row.name);
                    read_blob_heap_index(reader, row.signature);
                    read_index(reader, row.param_list, needs_wide_index(PeCliMetadataTableId::Param));

                    _method_def_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::MethodImpl:
                _method_impl_table = std::make_unique<std::vector<PeCliMetadataRowMethodImpl>>();
                _method_impl_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowMethodImpl  row;
                    read_index(reader, row.class_, needs_wide_index(PeCliMetadataTableId::TypeDef));
                    read_index(reader, row.method_body, needs_wide_index_vec({PeCliMetadataTableId::MethodDef, PeCliMetadataTableId::MemberRef}));
                    read_index(reader, row.method_declaration, needs_wide_index_vec({PeCliMetadataTableId::MethodDef, PeCliMetadataTableId::MemberRef}));

                    _method_impl_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::MethodSemantics:
                _method_semantics_table = std::make_unique<std::vector<PeCliMetadataRowMethodSemantics>>();
                _method_semantics_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowMethodSemantics row;
                    reader.read(row.semantics);
                    read_index(reader, row.method, needs_wide_index(PeCliMetadataTableId::MethodDef));
                    read_index(reader, row.association, needs_wide_index_vec({PeCliMetadataTableId::Event, PeCliMetadataTableId::Property}));

                    _method_semantics_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::MethodSpec:
                _method_spec_table = std::make_unique<std::vector<PeCliMetadataRowMethodSpec>>();
                _method_spec_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowMethodSpec  row;
                    read_index(reader, row.method, needs_wide_index_vec({PeCliMetadataTableId::MethodDef, PeCliMetadataTableId::MemberRef}));
                    read_blob_heap_index(reader, row.instantiation);

                    _method_spec_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::Module:
                _module_table = std::make_unique<std::vector<PeCliMetadataRowModule>>();
                _module_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowModule  row;
                    reader.read(row.generation);
                    read_strings_heap_index(reader, row.name);
                    read_guid_heap_index(reader, row.mv_id);
                    read_guid_heap_index(reader, row.enc_id);
                    read_guid_heap_index(reader, row.enc_base_id);

                    _module_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::ModuleRef:
                _module_ref_table = std::make_unique<std::vector<PeCliMetadataRowModuleRef>>();
                _module_ref_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowModuleRef   row;
                    read_strings_heap_index(reader, row.name);

                    _module_ref_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::NestedClass:
                _nested_class_table = std::make_unique<std::vector<PeCliMetadataRowNestedClass>>();
                _nested_class_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowNestedClass row;
                    bool                        use_wide = needs_wide_index(PeCliMetadataTableId::TypeDef);
                    read_index(reader, row.nested_class, use_wide);
                    read_index(reader, row.enclosing_class, use_wide);

                    _nested_class_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::Param:
                _param_table = std::make_unique<std::vector<PeCliMetadataRowParam>>();
                _param_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowParam   row;
                    reader.read(row.flags);
                    reader.read(row.sequence);
                    read_strings_heap_index(reader, row.name);

                    _param_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::Property:
                _property_table = std::make_unique<std::vector<PeCliMetadataRowProperty>>();
                _property_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowProperty    row;
                    reader.read(row.flags);
                    read_strings_heap_index(reader, row.name);
                    read_blob_heap_index(reader, row.type);

                    _property_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::PropertyMap:
                _property_map_table = std::make_unique<std::vector<PeCliMetadataRowPropertyMap>>();
                _property_map_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowPropertyMap row;
                    read_index(reader, row.parent, needs_wide_index(PeCliMetadataTableId::TypeDef));
                    read_index(reader, row.property_list, needs_wide_index(PeCliMetadataTableId::Property));

                    _property_map_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::StandAloneSig:
                _stand_alone_sig_table = std::make_unique<std::vector<PeCliMetadataRowStandAloneSig>>();
                _stand_alone_sig_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowStandAloneSig   row;
                    read_blob_heap_index(reader, row.signature);

                    _stand_alone_sig_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::TypeDef:
                _type_def_table = std::make_unique<std::vector<PeCliMetadataRowTypeDef>>();
                _type_def_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowTypeDef row;
                    reader.read(row.flags);
                    read_strings_heap_index(reader, row.type_name);
                    read_strings_heap_index(reader, row.type_namespace);
                    read_index(reader, row.extends, needs_wide_index_vec({PeCliMetadataTableId::TypeDef}));
                    read_index(reader, row.field_list, needs_wide_index(PeCliMetadataTableId::Field));
                    read_index(reader, row.method_list, needs_wide_index(PeCliMetadataTableId::MethodDef));

                    _type_def_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::TypeRef:
                _type_ref_table = std::make_unique<std::vector<PeCliMetadataRowTypeRef>>();
                _type_ref_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowTypeRef row;
                    read_index(reader, row.resolution_scope, needs_wide_index_vec({PeCliMetadataTableId::Module, PeCliMetadataTableId::ModuleRef, PeCliMetadataTableId::AssemblyRef, PeCliMetadataTableId::TypeRef}));
                    read_strings_heap_index(reader, row.type_name);
                    read_strings_heap_index(reader, row.type_namespace);

                    _type_ref_table->push_back(row);
                }
                break;
            case PeCliMetadataTableId::TypeSpec:
                _type_spec_table = std::make_unique<std::vector<PeCliMetadataRowTypeSpec>>();
                _type_spec_table->reserve(row_count);

                for (uint32_t j = 0; j < row_count; ++j)
                {
                    PeCliMetadataRowTypeSpec    row;
                    read_blob_heap_index(reader, row.signature);

                    _type_spec_table->push_back(row);
                }
                break;
            default:    // unknown table type. not much we can do since we would have to know the size of each row of the unknown table.
                throw std::runtime_error("Unknown CLI metadata table type");
        };
    }
}

void PeCli::load(std::istream &stream, const std::vector<PeSection> &sections, LoadOptions::Options options)
{
    read(stream, _cli_header.size);
    read(stream, _cli_header.major_runtime_version);
    read(stream, _cli_header.minor_runtime_version);
    read_data_directory_entry(stream, _cli_header.metadata);
    read(stream, _cli_header.flags);
    read(stream, _cli_header.entry_point_token);   // This is a member of a union. flags will tell us which actual member to use.
    read_data_directory_entry(stream, _cli_header.resources);
    read_data_directory_entry(stream, _cli_header.strong_name_signature);
    read_data_directory_entry(stream, _cli_header.code_manager_table);
    read_data_directory_entry(stream, _cli_header.vtable_fixups);
    read_data_directory_entry(stream, _cli_header.export_address_table_jumps);
    read_data_directory_entry(stream, _cli_header.managed_native_header);

    if (options | LoadOptions::LoadCliMetadata)
    {
        auto    rva{_cli_header.metadata.virtual_address};
        auto    section{find_section_by_rva(rva, sections)};

        if (section)
        {
            auto    pos{get_file_offset(rva, *section)};
            stream.seekg(pos);

            _metadata = std::make_unique<PeCliMetadata>();
            _metadata->load(stream, options);
        }
    }
    //TODO: Load any other CLI information!!!
}
