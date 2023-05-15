#ifndef _MAIN_LIST_H_
#define _MAIN_LIST_H_

#include <vector>

#include "ListView.h"
#include "FileInfo.h"
#include <ExeInfo.h>

class MainList : public ListView
{
public:
    MainList() = default;
    MainList(const MainList &) = delete;
    MainList(MainList &&) = delete;
    MainList &operator=(const MainList &) = delete;
    MainList &operator=(MainList &&) = delete;

    using ListView::Create;

    bool Create(DWORD style,
                const RECT &rect,
                Window *parent,
                UINT id) noexcept
    {
        return ListView::Create(L"Main List View",
                                style | LVS_REPORT,
                                rect,
                                parent,
                                id);
    }

    void clear() noexcept
    {
        delete_all();
        while (delete_column(0))
            ;
    }

    void populate_file_info(const FileInfo &info);
    void populate_mz(const MzExeHeader &header);

    void populate_ne(const NeExeInfo &info);
    void populate_ne_header(const NeExeInfo &info);
    void populate_ne_entry_table(const NeExeInfo::EntryTable &table);
    void populate_ne_entry_bundle(const NeEntryBundle &bundle);
    void populate_ne_segment_table(const NeExeInfo::SegmentTable &table, uint16_t alignment_shift);
    void populate_ne_names_table(const NeExeInfo::NameContainer &names);    // used for both Resident and Non-Resident name tables.
    void populate_ne_strings(const NeExeInfo::StringContainer &strings, bool show_length);
    void populate_ne_resource_table(const NeExeInfo::ResourceTable &resources) noexcept;
    void populate_ne_resource_entry(const NeResourceEntry &entry, uint16_t shift_count);
    void populate_ne_resource(const NeResource &resource, uint16_t shift_count);

    void populate_pe(const PeExeInfo &info);
    void populate_pe_file_header(const PeImageFileHeader &header);
    void populate_pe_optional_header32(const PeOptionalHeader32 &header);
    void populate_pe_optional_header64(const PeOptionalHeader64 &header);
    void populate_pe_data_directory(const PeExeInfo &peinfo);
    void populate_pe_section_headers(const PeExeInfo::SectionTable &section_table);
    //TODO: other populate_* functions here, for Import, Export, etc.
    void populate_pe_imports(const PeExeInfo::ImportDirectory &imports);
    void populate_pe_import_entry(const PeImportDirectoryEntry::LookupTable &table);
    void populate_pe_resource_dir(const PeResourceDirectory &resource_dir);
    void populate_pe_resource_dir_entry(const PeResourceDirectoryEntry &dir_entry);
    void populate_pe_resource_data_entry(const PeResourceDataEntry &data_entry);
    void populate_pe_exports(const PeExports &exports);
    void populate_pe_cli(const PeCli &cli);
    void populate_pe_cli_header(const PeCliHeader &header);
    void populate_pe_cli_metadata_header(const PeCliMetadataHeader &header);
    void populate_pe_cli_stream_headers(const std::vector<PeCliStreamHeader> &headers);
    void populate_pe_cli_stream_tables(const PeCliMetadata &metadata);
    void populate_pe_cli_strings_stream(const PeCliMetadata &metadata);
    void populate_pe_cli_us_stream(const PeCliMetadata &metadata);
    void populate_pe_cli_guid_stream(const PeCliMetadata &metadata);
    void populate_pe_cli_blob_stream(const PeCliMetadata &metadata);
    void populate_pe_cli_tables(const PeCliMetadataTablesStreamHeader &header);

    void populate_pe_cli_table(const std::vector<PeCliMetadataRowAssembly> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyOS> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyProcessor> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyRef> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyRefOS> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyRefProcessor> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowClassLayout> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowConstant> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowCustomAttribute> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowDeclSecurity> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowEvent> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowEventMap> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowExportedType> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowField> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowFieldLayout> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowFieldMarshal> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowFieldRVA> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowFile> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowGenericParam> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowGenericParamConstraint> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowImplMap> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowInterfaceImpl> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowManifestResource> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowMemberRef> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowMethodDef> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowMethodImpl> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowMethodSemantics> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowMethodSpec> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowModule> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowModuleRef> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowNestedClass> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowParam> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowProperty> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowPropertyMap> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowStandAloneSig> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowTypeDef> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowTypeRef> &table, const PeCliMetadata &metadata);
    void populate_pe_cli_table(const std::vector<PeCliMetadataRowTypeSpec> &table, const PeCliMetadata &metadata);


private:
    int populate_pe_optional_header_base(const PeOptionalHeaderBase &header);
};

#endif  // _MAIN_LIST_H_
