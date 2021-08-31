/// \file   PEExe.cpp
/// Implementation of PzExeInfo.
///
/// \author Jeff Bienstadt
///

#include <algorithm>
#include <exception>
#include <istream>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include "LoadOptions.h"
#include "PEExe.h"
#include "readstream.h"

namespace {

const PeSection *find_section_by_rva(uint32_t rva, const PeExeInfo::SectionTable &sections)
{
    for (size_t i = 0; i < sections.size(); ++i)
    {
        if (rva >= sections[i].virtual_address())
        {
            if (i == sections.size() - 1)
                return &sections[i];    // this is the last one, so it must be it.

            if (rva < sections[i+1].virtual_address())
                return &sections[i];
        }
    }

    return nullptr;
}

inline uint32_t get_file_offset(uint32_t rva, const PeSection &section)
{
    return rva - section.virtual_address() + section.header().raw_data_position;
}

#if !defined(EXELIB_NO_LOAD_FORWARDERS)
inline bool is_rva_within_section(uint32_t rva, const PeSection &section)
{
    return (rva >= section.virtual_address()) && (rva <= section.virtual_address() + section.size());
}
#endif

std::string read_sz_string(std::istream &stream)
{
    std::string rv;
    char        ch;

    while (true)
    {
        read(stream, &ch);
        if (ch == 0)
            break;
        rv.push_back(ch);
    }

    return rv;
}

}   // anonymous namespace

PeExeInfo::PeExeInfo(std::istream &stream, size_t header_location, LoadOptions::Options options)
    : _header_position{header_location}
{
    load_image_file_header(stream);

    if (_image_file_header.optional_header_size != 0)    // should be zero only for object files, never for image files.
    {
        uint32_t nRVAs = 0;

        uint16_t magic;
        read(stream, &magic);
        stream.seekg(-static_cast<int>(sizeof(magic)), std::ios::cur);

        bool using_64{false};

        if (magic == 0x010B)        // 32-bit optional header
        {
            _optional_32 = std::make_unique<PeOptionalHeader32>();
            load_optional_header_32(stream);
            nRVAs = _optional_32->num_rva_and_sizes;
        }
        else if (magic == 0x020B)   // 64-bit optional header
        {
            _optional_64 = std::make_unique<PeOptionalHeader64>();
            load_optional_header_64(stream);
            nRVAs = _optional_64->num_rva_and_sizes;
            using_64 = true;
        }
        else                        // unrecognized optional header type
        {
            //TODO: Indicate an error? Throw?
        }

        // Load the Data Directory
        _data_directory.reserve(nRVAs);
        for (uint32_t i = 0; i < nRVAs; ++i)
        {
            PeDataDirectoryEntry entry;
            read(stream, &entry.virtual_address);
            read(stream, &entry.size);

            _data_directory.push_back(entry);
        }

        // Load the sections; headers and optionally raw data
        _sections.reserve(_image_file_header.num_sections);
        for (uint16_t i = 0; i < _image_file_header.num_sections; ++i)
        {
            // load the section header
            PeSectionHeader header;

            stream.read(reinterpret_cast<char *>(&header.name), (sizeof(header.name) / sizeof(header.name[0])));
            read(stream, &header.virtual_size);
            read(stream, &header.virtual_address);
            read(stream, &header.size_of_raw_data);
            read(stream, &header.raw_data_position);
            read(stream, &header.relocations_position);
            read(stream, &header.line_numbers_position);
            read(stream, &header.number_of_relocations);
            read(stream, &header.number_of_line_numbers);
            read(stream, &header.characteristics);

            if (options & LoadOptions::LoadSectionData)
            {
                std::vector<uint8_t>    data;
                auto data_size = std::min(header.virtual_size, header.size_of_raw_data);
                if (data_size)
                {
                    data.resize(data_size);
                    auto here = stream.tellg();
                    stream.seekg(header.raw_data_position);
                    stream.read(reinterpret_cast<char *>(&data[0]), data_size);
                    stream.seekg(here);
                }

                _sections.emplace_back(header, std::move(data));
            }
            else
            {
                _sections.emplace_back(header);
            }
        }

        // Load Export Table
        load_exports(stream);

        // Load Import Table
        load_imports(stream, using_64);

        // Load Debug Directory
        load_debug_directory(stream, options);

        //TODO: Load more here!!!
    }
    else
    {
        throw std::runtime_error("Not a PE executable file. Perhaps a COFF object file?");
    }
}

void PeExeInfo::load_image_file_header(std::istream &stream)
{
    read(stream, &_image_file_header.signature);
    if (_image_file_header.signature != PeImageFileHeader::pe_signature)
        throw std::runtime_error("not a PE executable file.");

    read(stream, &_image_file_header.target_machine);
    read(stream, &_image_file_header.num_sections);
    read(stream, &_image_file_header.timestamp);
    read(stream, &_image_file_header.symbol_table_offset);
    read(stream, &_image_file_header.num_symbols);
    read(stream, &_image_file_header.optional_header_size);
    read(stream, &_image_file_header.characteristics);
}

void PeExeInfo::load_optional_header_base(std::istream &stream, PeOptionalHeaderBase &header)
{
    read(stream, &header.magic);
    read(stream, &header.linker_version_major);
    read(stream, &header.linker_version_minor);
    read(stream, &header.code_size);
    read(stream, &header.initialized_data_size);
    read(stream, &header.uninitialized_data_size);
    read(stream, &header.address_of_entry_point);
    read(stream, &header.base_of_code);
}

void PeExeInfo::load_optional_header_32(std::istream &stream)
{
    if (!_optional_32)
        throw std::runtime_error("Cannot read into empty PE optional header (32-bit)");

    auto  &header = *_optional_32;

    load_optional_header_base(stream, header);
    read(stream, &header.base_of_data);
    read(stream, &header.image_base);
    read(stream, &header.section_alignment);
    read(stream, &header.file_alignment);
    read(stream, &header.os_version_major);
    read(stream, &header.os_version_minor);
    read(stream, &header.image_version_major);
    read(stream, &header.image_version_minor);
    read(stream, &header.subsystem_version_major);
    read(stream, &header.subsystem_version_minor);
    read(stream, &header.win32_version_value);
    read(stream, &header.size_of_image);
    read(stream, &header.size_of_headers);
    read(stream, &header.checksum);
    read(stream, &header.subsystem);
    read(stream, &header.dll_characteristics);
    read(stream, &header.size_of_stack_reserve);
    read(stream, &header.size_of_stack_commit);
    read(stream, &header.size_of_heap_reserve);
    read(stream, &header.size_of_heap_commit);
    read(stream, &header.loader_flags);
    read(stream, &header.num_rva_and_sizes);
}

void PeExeInfo::load_optional_header_64(std::istream &stream)
{
    if (!_optional_64)
        throw std::runtime_error("Cannot read into empty PE optional header (64-bit)");

    auto  &header = *_optional_64;

    load_optional_header_base(stream, header);
    read(stream, &header.image_base);
    read(stream, &header.section_alignment);
    read(stream, &header.file_alignment);
    read(stream, &header.os_version_major);
    read(stream, &header.os_version_minor);
    read(stream, &header.image_version_major);
    read(stream, &header.image_version_minor);
    read(stream, &header.subsystem_version_major);
    read(stream, &header.subsystem_version_minor);
    read(stream, &header.win32_version_value);
    read(stream, &header.size_of_image);
    read(stream, &header.size_of_headers);
    read(stream, &header.checksum);
    read(stream, &header.subsystem);
    read(stream, &header.dll_characteristics);
    read(stream, &header.size_of_stack_reserve);
    read(stream, &header.size_of_stack_commit);
    read(stream, &header.size_of_heap_reserve);
    read(stream, &header.size_of_heap_commit);
    read(stream, &header.loader_flags);
    read(stream, &header.num_rva_and_sizes);
}


void PeExeInfo::load_exports(std::istream &stream)
{
    if (_data_directory.size() >= 1 && _data_directory[0].size > 0)
    {
        auto    rva{_data_directory[0].virtual_address};
        auto    section{find_section_by_rva(rva, _sections)};

        if (section)
        {
            _exports = std::make_unique<PeExports>();

            auto    pos{get_file_offset(rva, *section)};
            auto    here{stream.tellg()};
            stream.seekg(pos);

            auto    &exports_directory = _exports->directory;
            read(stream, &exports_directory.export_flags);
            read(stream, &exports_directory.timestamp);
            read(stream, &exports_directory.version_major);
            read(stream, &exports_directory.version_minor);
            read(stream, &exports_directory.name_rva);
            read(stream, &exports_directory.ordinal_base);
            read(stream, &exports_directory.num_address_table_entries);
            read(stream, &exports_directory.num_name_pointers);
            read(stream, &exports_directory.export_address_rva);
            read(stream, &exports_directory.name_pointer_rva);
            read(stream, &exports_directory.ordinal_table_rva);

            stream.seekg(get_file_offset(exports_directory.name_rva, *section));
            _exports->name = read_sz_string(stream);

            // Load the Export Address Table
#if !defined(EXELIB_NO_LOAD_FORWARDERS)
            if (exports_directory.num_address_table_entries)
            {
                stream.seekg(get_file_offset(exports_directory.export_address_rva, *section));
                for (uint32_t i = 0; i < exports_directory.num_address_table_entries; ++i)
                {
                    PeExportAddressTableEntry   entry;

                    read(stream, &entry.export_rva);
                    if (entry.export_rva != 0)  //NOTE: We probably should not have to do this check
                        entry.is_forwarder = is_rva_within_section(entry.export_rva, *section);
                    else
                        entry.is_forwarder = false;
                    if (entry.is_forwarder)
                        _exports->forward_indices.push_back(i);
                    _exports->address_table.push_back(entry);
                }

                // get the forwarder strings
                for (auto &&entry : _exports->address_table)
                {
                    if (entry.is_forwarder)
                    {
                        auto pos = get_file_offset(entry.export_rva, *section);
                        stream.seekg(pos);
                        entry.forwarder_name = read_sz_string(stream);
                    }
                }
            }
#else
            // Here we load the Export Address Table, but ignore the forwarders.
            if (exports_directory.num_address_table_entries)
            {
                stream.seekg(get_file_offset(exports_directory.export_address_rva, *section));
                for (uint32_t i = 0; i < exports_directory.num_address_table_entries; ++i)
                {
                    PeExportAddressTableEntry   entry;

                    read(stream, &entry.export_rva);
                    _exports->address_table.push_back(entry);
                }
            }
#endif

            // Load the Export Name Pointer Table, the Export Ordinal Table, and the Export Name Table
            if (exports_directory.num_name_pointers)
            {
                auto pos = get_file_offset(exports_directory.name_pointer_rva, *section);
                stream.seekg(pos);
                _exports->name_pointer_table.resize(exports_directory.num_name_pointers);
                stream.read(reinterpret_cast<char *>(_exports->name_pointer_table.data()), _exports->name_pointer_table.size() * sizeof(_exports->name_pointer_table[0]));

                pos = get_file_offset(exports_directory.ordinal_table_rva, *section);
                stream.seekg(pos);
                _exports->ordinal_table.resize(exports_directory.num_name_pointers);
                stream.read(reinterpret_cast<char *>(_exports->ordinal_table.data()), _exports->ordinal_table.size() * sizeof(_exports->ordinal_table[0]));

                _exports->name_table.reserve(exports_directory.num_name_pointers);
                for (auto rva : _exports->name_pointer_table)
                {
                    pos = get_file_offset(rva, *section);
                    stream.seekg(pos);
                    _exports->name_table.emplace_back(read_sz_string(stream));
                }
            }

            stream.seekg(here);
        }
    }
}

void PeExeInfo::load_imports(std::istream &stream, bool using_64)
{
    if (_data_directory.size() >= 2 && _data_directory[1].size > 0)
    {
        auto    rva{_data_directory[1].virtual_address};
        auto    section{find_section_by_rva(rva, _sections)};

        if (section)
        {
            _imports = std::make_unique<ImportDirectory>();

            auto    pos{get_file_offset(rva, *section)};
            auto    here{stream.tellg()};
            stream.seekg(pos);

            PeImportDirectoryEntry  entry;
            while (true)
            {
                read(stream, &entry.import_lookup_table_rva);
                read(stream, &entry.timestamp);
                read(stream, &entry.forwarder_chain);
                read(stream, &entry.name_rva);
                read(stream, &entry.import_address_table_rva);

                if (   entry.import_lookup_table_rva == 0
                    && entry.timestamp == 0
                    && entry.forwarder_chain == 0
                    && entry.name_rva == 0
                    && entry.import_address_table_rva == 0)
                    break;

                _imports->push_back(entry);
            }
            // Load the DLL names
            for (auto &&entry : *_imports)
            {
                stream.seekg(get_file_offset(entry.name_rva, *section));
                entry.module_name = read_sz_string(stream);

                stream.seekg(get_file_offset(entry.import_address_table_rva, *section));
                while (true)
                {
                    PeImportLookupEntry lookup_entry {0};
                    if (using_64)
                    {
                        uint64_t value;
                        read(stream, &value);
                        if (value == 0)
                            break;
                        if (value & 0x8000000000000000)
                        {
                            lookup_entry.ord_name_flag = 1;
                            lookup_entry.ordinal = value & 0xFFFF;
                        }
                        else
                        {
                            lookup_entry.ord_name_flag = 0;
                            lookup_entry.name_rva = value & 0x7FFFFFFF;
                        }
                    }
                    else
                    {
                        uint32_t value;
                        read(stream, &value);
                        if (value == 0)
                            break;
                        if (value & 0x80000000)
                        {
                            lookup_entry.ord_name_flag = 1;
                            lookup_entry.ordinal = value & 0xFFFF;
                        }
                        else
                        {
                            lookup_entry.ord_name_flag = 0;
                            lookup_entry.name_rva = value & 0x7FFFFFFF;
                        }
                    }

                    if (lookup_entry.ord_name_flag == 0)
                    {
                        auto here = stream.tellg();
                        stream.seekg(get_file_offset(lookup_entry.name_rva, *section));
                        read(stream, &lookup_entry.hint);
                        lookup_entry.name = read_sz_string(stream);

                        stream.seekg(here);
                    }
                    entry.lookup_table.push_back(lookup_entry);
                }
            }
            stream.seekg(here);
        }
    }
}

void PeExeInfo::load_debug_directory(std::istream &stream, LoadOptions::Options options)
{
    if (_data_directory.size() >= 7 && _data_directory[6].size > 0)
    {
        auto    rva{_data_directory[6].virtual_address};
        auto    section{find_section_by_rva(rva, _sections)};

        if (section)
        {
            const size_t    directory_size{_data_directory[6].size};
            size_t          bytes_read{0};

            auto    pos{get_file_offset(rva, *section)};
            auto    here{stream.tellg()};
            stream.seekg(pos);

            while (bytes_read < directory_size)
            {
                PeDebugDirectoryEntry   entry;
                bytes_read += read(stream, &entry.characteristics);
                bytes_read += read(stream, &entry.timestamp);
                bytes_read += read(stream, &entry.version_major);
                bytes_read += read(stream, &entry.version_minor);
                bytes_read += read(stream, &entry.type);
                bytes_read += read(stream, &entry.size_of_data);
                bytes_read += read(stream, &entry.address_of_raw_data);
                bytes_read += read(stream, &entry.pointer_to_raw_data);

                entry.data_loaded = false;
                _debug_directory.emplace_back(std::move(entry));
            }

            // Load debug data
            for (auto &&entry : _debug_directory)
            {
                // There are few types that we know how to handle,
                // so we'll load their data regardless of the options flags
                switch (entry.type)
                {
                    case static_cast<std::underlying_type<PeDebugType>::type>(PeDebugType::CodeView):
                    //case static_cast<std::underlying_type<PeDebugType>::type>(PeDebugType::VC_FEATURE):
#if !defined(NO_DEBUG_MISC_TYPE)
                    case static_cast<std::underlying_type<PeDebugType>::type>(PeDebugType::Misc):
#endif
                    {
                        entry.data.resize(entry.size_of_data);
                        stream.seekg(entry.pointer_to_raw_data);
                        stream.read(reinterpret_cast<char *>(entry.data.data()), entry.data.size());
                        entry.data_loaded = true;
                        break;
                    }

                    default:
                    {
                        if (options & LoadOptions::LoadDebugData)
                        {
                            entry.data.resize(entry.size_of_data);
                            stream.seekg(entry.pointer_to_raw_data);
                            stream.read(reinterpret_cast<char *>(entry.data.data()), entry.data.size());
                            entry.data_loaded = true;
                        }
                        break;
                    }
                }
            }

            stream.seekg(here);
        }
        else
        {
            //TODO: It is possible for the Debug Directory to be outside the
            //      boundaries of any Section. Not sure how to find the directory
            //      in the file without a section to refer to.
        }
    }
}
