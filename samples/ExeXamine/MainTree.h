#ifndef _MAIN_TREE_H_
#define _MAIN_TREE_H_

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
    peImports,
    peImportEntry,
    peImportLookupEntry,
    peExports,
    peRelocations,
    peDebug,
    peResources,
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
    /*
    HTREEITEM add_item(const wchar_t *item_text, const TreeItemData *data, HTREEITEM parent, HTREEITEM previous) noexcept
    {
        TVITEM          tvitem{};
        TVINSERTSTRUCT  tv_insert{};

        tvitem.mask = TVIF_TEXT     // TODO: Add image flags later
                    | TVIF_PARAM;

        tvitem.pszText = const_cast<LPWSTR>(item_text);
        tvitem.cchTextMax = 0;  // not used when setting

        //TODO: Add images later

        tvitem.lParam = reinterpret_cast<LPARAM>(data);
        tv_insert.item = tvitem;
        tv_insert.hParent = parent;
        tv_insert.hInsertAfter = previous ? previous : TVI_LAST;

        //return (HTREEITEM)SendMessage(handle(), TVM_INSERTITEM, 0, (LPARAM)(LPTVINSERTSTRUCT)&tv_insert);
        return TreeView_InsertItem(handle(), &tv_insert);
    }
*/
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
};

#endif  // _MAIN_TREE_H_
