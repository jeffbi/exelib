#ifndef _MAIN_TREE_H_
#define _MAIN_TREE_H_

#include <array>

#include "TreeView.h"


enum class TreeItemDataType
{
    nothing = 0,
    fileInfo,
    dosHeader,

    neArea,
    neHeader,
    neEntryTable,
    neEntryBundle,
    neSegmentTable,
    neResidentNamesTable,
    neNonResidentNamesTable,
    neImportedNamesTable,
    neModuleNamesTable,
    neResourceTable,
    neResourceEntry,
    neResource,

    peArea,
    peFileHeader,
    peOptionalHeader32,
    peOptionalHeader64,
    peDataDirectory,
    peSectionHeaders,
    peImportDirectory,
    peImportEntry,
    peImportLookupEntry,
    peExports,
    peRelocations,
    peDebug,
    peResourceDir,
    peResourceDirEntry,
    peResourceDataEntry,
    peCli,
    peCliHeader,
    peCliMetadataHeader,
    peCliStreamsHeader,
    peCliStreamTables,
    peCliStreamStrings,
    peCliStreamUserStrings,
    peCliStreamGuid,
    peCliStreamBlob,
    peCliTables,    // show valid tables bitmap in list
    peCliTableAssembly,
    peCliTableAssemblyOS,
    peCliTableAssemblyProcessor,
    peCliTableAssemblyRef,
    peCliTableAssemblyRefOS,
    peCliTableAssemblyRefProcessor,
    peCliTableClassLayout,
    peCliTableConstant,
    peCliTableCustomAttribute,
    peCliTableDeclSecurity,
    peCliTableEvent,
    peCliTableEventMap,
    peCliTableExportedType,
    peCliTableField,
    peCliTableFieldLayout,
    peCliTableFieldMarshal,
    peCliTableFieldRVA,
    peCliTableFile,
    peCliTableGenericParam,
    peCliTableGenericParamConstraint,
    peCliTableImplMap,
    peCliTableInterfaceImpl,
    peCliTableManifestResource,
    peCliTableMemberRef,
    peCliTableMethodDef,
    peCliTableMethodImpl,
    peCliTableMethodSemantics,
    peCliTableMethodSpec,
    peCliTableModule,
    peCliTableModuleRef,
    peCliTableNestedClass,
    peCliTableParam,
    peCliTableProperty,
    peCliTablePropertyMap,
    peCliTableStandAloneSig,
    peCliTableTypeDef,
    peCliTableTypeRef,
    peCliTableTypeSpec,
};

struct TreeItemData
{
    TreeItemDataType    type;
    const void         *data;   // Much of the time this will be nullptr
};


class MainTree : public TreeView
{
public:
    MainTree() = default;
    MainTree(const MainTree &) = delete;
    MainTree(MainTree &&) = delete;
    MainTree &operator=(const MainTree &) = delete;
    MainTree &operator=(MainTree &&) = delete;

    using TreeView::Create;

    bool Create(DWORD style,
                const RECT &rect,
                Window *parent,
                UINT id) noexcept
    {
        return TreeView::Create(L"Main Tree View",
                                style | TVS_HASLINES | TVS_HASBUTTONS | TVS_DISABLEDRAGDROP | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
                                rect,
                                parent,
                                id);
    }

    HTREEITEM add_item(const wchar_t *item_text, TreeItemDataType data_type, const void *data, HTREEITEM parent, HTREEITEM previous) noexcept
    {
        TVITEM          tvitem{};
        TVINSERTSTRUCT  tv_insert{};

        tvitem.mask = TVIF_TEXT     // TODO: Add image flags later
                    | TVIF_PARAM;

        tvitem.pszText = const_cast<LPWSTR>(item_text);
        tvitem.cchTextMax = 0;  // not used when setting

        //TODO: Add images later

        tvitem.lParam = reinterpret_cast<LPARAM>(new TreeItemData{data_type, data});
        tv_insert.item = tvitem;
        tv_insert.hParent = parent;
        tv_insert.hInsertAfter = previous ? previous : TVI_LAST;

        return TreeView_InsertItem(handle(), &tv_insert);
    }

    HTREEITEM add_item(const wchar_t *item_text, TreeItemDataType data_type, HTREEITEM parent, HTREEITEM previous) noexcept
    {
        return add_item(item_text, data_type, nullptr, parent, previous);
    }

    HTREEITEM add_resource_directory(const PeResourceDirectory *directory, HTREEITEM parent, HTREEITEM previous) noexcept
    {
        HTREEITEM   item{add_item(L"Resource Directory", TreeItemDataType::peResourceDir, directory, parent, previous)};

        for (const auto &entry : directory->name_entries)
        {
            add_resource_dir_entry(&entry, directory->level, item, nullptr);
        }
        for (const auto &entry : directory->id_entries)
        {
            add_resource_dir_entry(&entry, directory->level, item, nullptr);
        }

        return item;
    }

    HTREEITEM add_resource_dir_entry(const PeResourceDirectoryEntry *dir_entry, size_t level, HTREEITEM parent, HTREEITEM previous)
    {
        static constexpr std::array resource_types
                            {
                                L"???_0",
                                L"CURSOR",
                                L"BITMAP",
                                L"ICON",
                                L"MENU",
                                L"DIALOG",
                                L"STRING",
                                L"FONTDIR",
                                L"FONT",
                                L"ACCELERATORS",
                                L"RCDATA",
                                L"MESSAGETABLE",
                                L"GROUP CURSOR",
                                L"???_13",
                                L"GROUP_ICON",
                                L"???_15",
                                L"VERSION",
                                L"DLGINCLUDE",
                                L"???_18",
                                L"PLUGPLAY",
                                L"VXD",
                                L"ANICURSOR",
                                L"ANIICON",
                                L"HTML",
                                L"MANIFEST"
                            };

        std::wstring    text{L"Directory Entry, "};
        if (dir_entry->name_offset_or_int_id & 0x80000000)
        {
            text += L"Name: \"" + dir_entry->name + L'"';
        }
        else
        {
            text += L"ID: " + std::to_wstring(dir_entry->name_offset_or_int_id);
            if (level == 0)
            {
                text += L" (";
                if (dir_entry->name_offset_or_int_id < resource_types.size())
                    text += resource_types[dir_entry->name_offset_or_int_id];
                else
                    text += L"???_" + std::to_wstring(dir_entry->name_offset_or_int_id);
                text += ')';
            }
        }

        HTREEITEM   item{add_item(text.c_str(), TreeItemDataType::peResourceDirEntry, dir_entry, parent, previous)};

        if (dir_entry->next_dir)
            add_resource_directory(dir_entry->next_dir.get(), item, nullptr);
        else if (dir_entry->data_entry)
            add_item(L"Resource Data Entry", TreeItemDataType::peResourceDataEntry, dir_entry->data_entry.get(), item, previous);

        return item;
    }
};

#endif  // _MAIN_TREE_H_
