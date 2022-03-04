#include <array>
#include <filesystem>
#include <fstream>
#include <string>

#include <tchar.h>
#include <strsafe.h>

//#include "pch.h"    // pre-compiled headers
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif
#include <commdlg.h>

#include "resource.h"
#include "string_helpers.h"

#include "MainWindow.h"

LRESULT CALLBACK MainWindow::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    MainWindow *this_ptr{nullptr};

    if (msg == WM_NCCREATE)
    {
        CREATESTRUCT   *pc = reinterpret_cast<CREATESTRUCT *>(lParam);

        this_ptr = static_cast<MainWindow *>(pc->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this_ptr));

        this_ptr->handle(hwnd);
    }
    else
    {
        this_ptr = reinterpret_cast<MainWindow *>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }

    if (this_ptr)
        return this_ptr->handle_message(msg, wParam, lParam);
    else
        return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::handle_message(UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_CREATE:
            create_child_windows();
            return 0;

        case WM_COMMAND:
            on_command(wParam, lParam);
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_NOTIFY:
            return on_notify(wParam, lParam);

        case WM_SIZE:
            on_size(wParam, LOWORD(lParam), HIWORD(lParam));
            return 0;

        default:
            return DefWindowProc(handle(), msg, wParam, lParam);
    }
}

void MainWindow::on_size([[maybe_unused]]WPARAM sizing_type, int width, int height) noexcept
{
    RECT    client_rect;
    GetClientRect(handle(), &client_rect);

    _main_tree.move(client_rect.left, client_rect.top, 400, height, true);
    _main_list.move(client_rect.left + 400, client_rect.top, width - 400, height, true);
}

void MainWindow::on_command(WPARAM wParam, [[maybe_unused]]LPARAM lParam)
{
    switch (LOWORD(wParam))
    {
        case ID_FILE_OPEN:
            on_file_open();
            break;

        case ID_FILE_EXIT:
            SendMessage(handle(), WM_CLOSE, 0, 0);
            break;

        default:
            break;
    }
}

int MainWindow::on_notify([[maybe_unused]] WPARAM wParam, LPARAM lParam)
{
    const NMHDR *nmhdr{reinterpret_cast<NMHDR *>(lParam)};

    switch (nmhdr->code)
    {
        case TVN_SELCHANGED:
            on_notify_tvn_sel_changed(reinterpret_cast<NMTREEVIEW *>(lParam));
            break;

        case TVN_DELETEITEM:
            delete (reinterpret_cast<TreeItemData *>((reinterpret_cast<NMTREEVIEWA *>(lParam))->itemOld.lParam));
            break;

        default:
            break;
    }

    return 0;
}


void MainWindow::on_notify_tvn_sel_changed(const NMTREEVIEW *view)
{
    //const auto type{static_cast<TreeItemDataType>(view->itemNew.lParam)};

    //switch (type)

    const auto *item_info{reinterpret_cast<TreeItemData *>(view->itemNew.lParam)};
    switch (item_info->type)
    {
        case TreeItemDataType::nothing:
            _main_list.clear();
            break;

        case TreeItemDataType::fileInfo:
            _main_list.populate_file_info(_file_info);
            break;

        case TreeItemDataType::dosHeader:
            _main_list.populate_mz(_exe_info->mz_part()->header());
            break;


        // NE information
        case TreeItemDataType::neArea:
            _main_list.populate_ne(*_exe_info->ne_part());
            break;

        case TreeItemDataType::neHeader:
            _main_list.populate_ne_header(*_exe_info->ne_part());
            break;

        case TreeItemDataType::neEntryTable:
            _main_list.populate_ne_entry_table(_exe_info->ne_part()->entry_table());
            break;

        case TreeItemDataType::neEntryBundle:
            {
                const auto *bundle{static_cast<const NeEntryBundle *>(item_info->data)};
                _main_list.populate_ne_entry_bundle(*bundle);
            }
            break;

        case TreeItemDataType::neSegmentTable:
            _main_list.populate_ne_segment_table(_exe_info->ne_part()->segment_table(), _exe_info->ne_part()->align_shift_count());
            break;

        case TreeItemDataType::neResidentNamesTable:
            _main_list.populate_ne_names_table(_exe_info->ne_part()->resident_names());
            break;

        case TreeItemDataType::neNonResidentNamesTable:
            _main_list.populate_ne_names_table(_exe_info->ne_part()->nonresident_names());
            break;

        case TreeItemDataType::neImportedNamesTable:
            _main_list.populate_ne_strings(_exe_info->ne_part()->imported_names(), true);
            break;

        case TreeItemDataType::neModuleNamesTable:
            _main_list.populate_ne_strings(_exe_info->ne_part()->module_names(), false);
            break;

        case TreeItemDataType::neResourceTable:
            _main_list.populate_ne_resource_table(_exe_info->ne_part()->resource_table());
            break;

        case TreeItemDataType::neResourceEntry:
            {
                const auto *entry{static_cast<const NeResourceEntry *>(item_info->data)};
                _main_list.populate_ne_resource_entry(*entry, _exe_info->ne_part()->resource_shift_count());
            }
            break;

        case TreeItemDataType::neResource:
            {
                const auto *resource{static_cast<const NeResource *>(item_info->data)};
                _main_list.populate_ne_resource(*resource, _exe_info->ne_part()->resource_shift_count());
            }
            break;


        // PE information
        case TreeItemDataType::peArea:
            _main_list.populate_pe(*_exe_info->pe_part());
            break;

        case TreeItemDataType::peFileHeader:
            _main_list.populate_pe_file_header(_exe_info->pe_part()->header());
            break;

        case TreeItemDataType::peOptionalHeader32:
            _main_list.populate_pe_optional_header32(*_exe_info->pe_part()->optional_header_32());
            break;

        case TreeItemDataType::peOptionalHeader64:
            _main_list.populate_pe_optional_header64(*_exe_info->pe_part()->optional_header_64());
            break;

        case TreeItemDataType::peDataDirectory:
            _main_list.populate_pe_data_directory(*_exe_info->pe_part());
            break;

        case TreeItemDataType::peSectionHeaders:
            _main_list.populate_pe_section_headers(_exe_info->pe_part()->sections());
            break;

        //TODO: other cases here, for Import, export, etc.
        case TreeItemDataType::peImports:
        case TreeItemDataType::peExports:
        case TreeItemDataType::peResources:
        case TreeItemDataType::peRelocations:
        case TreeItemDataType::peDebug:
            break;

        case TreeItemDataType::peCli:
            _main_list.populate_pe_cli(*_exe_info->pe_part()->cli());
            break;

        case TreeItemDataType::peCliHeader:
            _main_list.populate_pe_cli_header(_exe_info->pe_part()->cli()->header());
            break;

        case TreeItemDataType::peCliMetadataHeader:
            _main_list.populate_pe_cli_metadata_header(_exe_info->pe_part()->cli()->metadata()->header());
            break;

        case TreeItemDataType::peCliStreamsHeader:
            _main_list.populate_pe_cli_stream_headers(_exe_info->pe_part()->cli()->metadata()->stream_headers());
            break;

        case TreeItemDataType::peCliStreamTables:
            _main_list.populate_pe_cli_stream_tables(*_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliStreamStrings:
            _main_list.populate_pe_cli_strings_stream(*_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliStreamUserStrings:
            _main_list.populate_pe_cli_us_stream(*_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliStreamGuid:
            _main_list.populate_pe_cli_guid_stream(*_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliStreamBlob:
            _main_list.populate_pe_cli_blob_stream(*_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTables:
            _main_list.populate_pe_cli_tables(_exe_info->pe_part()->cli()->metadata()->metadata_tables()->header());
            break;

        case TreeItemDataType::peCliTableAssembly:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->assembly_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableAssemblyOS:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->assembly_os_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableAssemblyProcessor:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->assembly_processor_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableAssemblyRef:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->assembly_ref_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableAssemblyRefOS:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->assembly_ref_os_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableAssemblyRefProcessor:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->assembly_ref_processor_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableClassLayout:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->class_layout_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableConstant:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->constant_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableCustomAttribute:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->custom_attribute_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableDeclSecurity:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->decl_security_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableEvent:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->event_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableEventMap:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->event_map_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableExportedType:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->exported_type_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableField:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->field_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableFieldLayout:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->field_layout_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableFieldMarshal:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->field_marshal_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableFieldRVA:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->field_rva_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableFile:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->file_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableGenericParam:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->generic_param_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableGenericParamConstraint:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->generic_param_constraint_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableImplMap:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->impl_map_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableInterfaceImpl:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->interface_impl_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableManifestResource:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->manifest_resource_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableMemberRef:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->member_ref_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableMethodDef:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->method_def_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableMethodImpl:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->method_impl_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableMethodSemantics:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->method_semantics_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableMethodSpec:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->method_spec_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableModule:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->module_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableModuleRef:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->module_ref_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableNestedClass:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->nested_class_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableParam:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->param_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableProperty:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->property_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTablePropertyMap:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->property_map_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableStandAloneSig:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->standalone_sig_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableTypeDef:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->type_def_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableTypeRef:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->type_ref_table(), *_exe_info->pe_part()->cli()->metadata());
            break;

        case TreeItemDataType::peCliTableTypeSpec:
            _main_list.populate_pe_cli_table(*_exe_info->pe_part()->cli()->metadata()->metadata_tables()->type_spec_table(), *_exe_info->pe_part()->cli()->metadata());
            break;
    }
}

void MainWindow::on_file_open()
{
    wchar_t         file_path[2048]{0};
    OPENFILENAME    ofn{sizeof(OPENFILENAME)};

    ofn.hwndOwner   = handle();
    ofn.hInstance   = nullptr;
    ofn.lpstrFilter = L"Executable Files\0*.EXE;*.DLL;*.FON\0All files\0*.*\0\0";
    ofn.lpstrCustomFilter   = nullptr;
    ofn.nMaxCustFilter      = 0;
    ofn.nFilterIndex        = 1;
    ofn.lpstrFile           = &file_path[0];
    ofn.nMaxFile            = 2048;
    ofn.lpstrFileTitle      = nullptr;
    ofn.nMaxFileTitle       = 0;
    ofn.lpstrInitialDir     = nullptr;
    ofn.lpstrTitle          = nullptr;
    ofn.Flags               = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.nFileOffset         = 0;
    ofn.nFileExtension      = 0;
    ofn.lpstrDefExt         = nullptr;
    ofn.lCustData           = 0;
    ofn.lpfnHook            = nullptr;
    ofn.lpTemplateName      = nullptr;
    ofn.pvReserved          = nullptr;
    ofn.dwReserved          = 0;
    ofn.FlagsEx             = 0;

    if (GetOpenFileName(&ofn))
    {
        load_file(ofn.lpstrFile);
    }
}

void MainWindow::create_child_windows() noexcept
{
    RECT    client_rect{};

    GetClientRect(handle(), &client_rect);

    RECT    tree_rect{client_rect};

    tree_rect.right = 400;

    _main_tree.Create(WS_CHILD | WS_VISIBLE | WS_BORDER,
                      tree_rect,
                      this,
                      ID_TREEVIEW);

    RECT    list_rect{client_rect};

    list_rect.left += 400;

    _main_list.Create(WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER,
                      list_rect,
                      this,
                      ID_LISTVIEW);
    _main_list.set_extended_style(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    _main_tree.set_focus();
}

void MainWindow::load_file(LPCTSTR file_path)
{
    clear_ui();
    _exe_info = nullptr;    // clear the current info

    std::ifstream   stream(file_path, std::ios_base::binary);

    if (stream.is_open())
    {
        try
        {
            _exe_info = std::make_unique<ExeInfo>(stream, LoadOptions::LoadAllData);
            set_file_info(file_path);
            reset_ui();
        }
        catch (const std::exception & /*ex*/)
        {
            std::wstring    message(L"Failed to load file ");
            message += file_path;
            MessageBox(handle(), message.c_str(), L"File load failure", MB_ICONEXCLAMATION);
        }
    }
    else
    {
        std::wstring    message(L"Failed to open file ");
        message += file_path;
        MessageBox(handle(), message.c_str(), L"File open failure", MB_ICONEXCLAMATION);
    }
}

void MainWindow::clear_ui() noexcept
{
    _main_list.clear();
    _main_tree.delete_all();
}

void MainWindow::reset_ui()
{
    clear_ui();
    populate_tree();
}

void MainWindow::populate_tree()
{
    HTREEITEM item_root{_main_tree.add_item(std::filesystem::path(_file_info.path).filename().c_str(), TreeItemDataType::fileInfo, nullptr, nullptr)};

    HTREEITEM item_dos_header{_main_tree.add_item(L"DOS Header", TreeItemDataType::dosHeader, item_root, nullptr)};
    _main_tree.expand(item_root, TVE_EXPAND);

    //TODO: Handle NE-style files!!!
    if (_exe_info->executable_type() == ExeType::NE && _exe_info->ne_part())
    {
        const auto *ne{_exe_info->ne_part()};
        HTREEITEM   item_ne_part{_main_tree.add_item(L"\"New\" Executable (NE)", TreeItemDataType::neArea, item_root, item_dos_header)};
        HTREEITEM   item_ne_header{_main_tree.add_item(L"NE Header", TreeItemDataType::neHeader, item_ne_part, nullptr)};

        HTREEITEM   item_ne_entry_table{_main_tree.add_item(L"Entry Table", TreeItemDataType::neEntryTable, item_ne_part, item_ne_header)};
        HTREEITEM   item_ne_segment_table{_main_tree.add_item(L"Segment Table", TreeItemDataType::neSegmentTable, item_ne_part, item_ne_entry_table)};
        HTREEITEM   item_ne_resident_names_table{_main_tree.add_item(L"Resident Names Table", TreeItemDataType::neResidentNamesTable, item_ne_part, item_ne_segment_table)};
        HTREEITEM   item_ne_non_resident_names_table{_main_tree.add_item(L"Non-Resident Names Table", TreeItemDataType::neNonResidentNamesTable, item_ne_part, item_ne_resident_names_table)};
        HTREEITEM   item_ne_imported_names_table{_main_tree.add_item(L"Imported Names Table", TreeItemDataType::neImportedNamesTable, item_ne_part, item_ne_non_resident_names_table)};
        HTREEITEM   item_ne_module_names_table{_main_tree.add_item(L"Module Names Table", TreeItemDataType::neModuleNamesTable, item_ne_part, item_ne_imported_names_table)};
        HTREEITEM   item_ne_resource_table{_main_tree.add_item(L"Resource Table", TreeItemDataType::neResourceTable, item_ne_part, item_ne_module_names_table)};

        HTREEITEM   item_previous{nullptr};

        //  Entry Table
        size_t  n_bundle{1};
        for (const auto &bundle : ne->entry_table())
        {
            std::array<wchar_t, 80> text_buffer{};

            StringCbPrintf(text_buffer.data(), text_buffer.size(), L"Bundle %llu (%llu)", n_bundle++, bundle.entries().size());
            item_previous = _main_tree.add_item(text_buffer.data(), TreeItemDataType::neEntryBundle, &bundle, item_ne_entry_table, item_previous);
        }

        //  Resource table
        for (const auto &entry : ne->resource_table())
        {
            std::wstring    type_name{entry.type & 0x8000 ? make_resource_type_name(entry.type) : make_wide(entry.type_name).value_or(L"")};
            item_previous = _main_tree.add_item(type_name.c_str(),
                                                TreeItemDataType::neResourceEntry, &entry,
                                                item_ne_resource_table, item_previous);
            HTREEITEM   item_res_previous{nullptr};
            for (const auto &resource : entry.resources)
            {
                std::wstring resource_name{resource.id & 0x8000 ? L'#' + std::to_wstring(resource.id & ~0x8000) : make_wide(resource.name).value_or(L"")};
                item_res_previous = _main_tree.add_item(resource_name.c_str(),
                                                        TreeItemDataType::neResource, &resource,
                                                        item_previous, item_res_previous);
            }

        }


        _main_tree.expand(item_ne_part, TVE_EXPAND);
    }
    // PE file data
    else if (_exe_info->executable_type() == ExeType::PE && _exe_info->pe_part())
    {
        const auto *pe{_exe_info->pe_part()};
        HTREEITEM item_pe_part{_main_tree.add_item(L"Portable Executable (PE)", TreeItemDataType::peArea, item_root, item_dos_header)};
        HTREEITEM item_file_header{_main_tree.add_item(L"File Header", TreeItemDataType::peFileHeader, item_pe_part, nullptr)};

        HTREEITEM item_opt_header{nullptr};

        if (pe->optional_header_32())
        {
            item_opt_header = _main_tree.add_item(L"Optional Header (32-bit)", TreeItemDataType::peOptionalHeader32, item_pe_part, item_file_header);
        }
        else if (pe->optional_header_64())
        {
            item_opt_header = _main_tree.add_item(L"Optional Header (64-bit)", TreeItemDataType::peOptionalHeader64, item_pe_part, item_file_header);
        }
        _main_tree.expand(item_pe_part, TVE_EXPAND);

        if (item_opt_header)
        {
            _main_tree.add_item(L"Data Directory", TreeItemDataType::peDataDirectory, item_opt_header, nullptr);
            _main_tree.expand(item_opt_header, TVE_EXPAND);
        }

        if (pe->sections().size())
        {
            _main_tree.add_item(L"Section Headers", TreeItemDataType::peSectionHeaders, item_pe_part, item_opt_header);
        }

        //TODO: We'll add entries for Import, Export, etc. later

        if (pe->has_cli())
        {
            HTREEITEM item_pe_cli{_main_tree.add_item(L".NET (CLI) Data", TreeItemDataType::peCli, item_pe_part, nullptr)};

            HTREEITEM item_pe_cli_header{_main_tree.add_item(L"CLI Header", TreeItemDataType::peCliHeader, item_pe_cli, nullptr)};

            HTREEITEM item_pe_cli_metadata_header{_main_tree.add_item(L"Metadata Header", TreeItemDataType::peCliMetadataHeader, item_pe_cli, item_pe_cli_header)};

            if (pe->cli()->metadata()->header().stream_count)
            {
                HTREEITEM   item_pe_cli_streams_header{_main_tree.add_item(L"Metadata Streams", TreeItemDataType::peCliStreamsHeader, item_pe_cli, item_pe_cli_metadata_header)};

                std::array<wchar_t, 80> name_buffer{0};
                HTREEITEM               previous_stream_item{nullptr};

                //for (size_t i = 0; i < pe->cli()->metadata()->header().stream_count; ++i)
                for (const auto &header : pe->cli()->metadata()->stream_headers())
                {
                    //const auto         &header{pe->cli()->metadata()->stream_headers()[i]};
                    TreeItemDataType    data_type{TreeItemDataType::nothing};
                    std::string         tmp_name{header.name};

                    if (tmp_name == "#~")
                    {
                        // do nothing
                    }
                    else if (tmp_name == "#Strings")
                    {
                        data_type = TreeItemDataType::peCliStreamStrings;
                        tmp_name += " (" + std::to_string(pe->cli()->metadata()->get_strings_heap_strings().size()) + ')';
                    }
                    else if (tmp_name == "#US")
                    {
                        data_type = TreeItemDataType::peCliStreamUserStrings;
                        tmp_name += " (" + std::to_string(pe->cli()->metadata()->get_us_heap_strings().size()) + ')';
                    }
                    else if (tmp_name == "#GUID")
                    {
                        data_type = TreeItemDataType::peCliStreamGuid;
                        tmp_name += " (" + std::to_string(pe->cli()->metadata()->get_guid_heap_guids().size()) + ')';
                    }
                    else if (tmp_name == "#Blob")
                    {
                        data_type = TreeItemDataType::peCliStreamBlob;
                        tmp_name += " (" + std::to_string(pe->cli()->metadata()->get_blob_heap_blobs().size()) + ')';
                    }
                    else    // Custom stream. Probably shouldn't be here, but we'll show it's name in the tree if we can.
                    {
                        if (tmp_name.size() > 32)   // ECMA-335 imposed limit.
                        {
                            tmp_name = "Invalid stream name--length > 32";
                        }
                    }
                    MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, tmp_name.c_str(), static_cast<int>(tmp_name.size() + 1), name_buffer.data(), 40);  // 40: a little more than the 32-char max
                    previous_stream_item = _main_tree.add_item(name_buffer.data(), data_type, item_pe_cli_streams_header, previous_stream_item);
                    if (header.name == "#~")
                    {
                        //TODO: Add tables sub-items!!!
                        HTREEITEM   pe_cli_tables{_main_tree.add_item(L"Tables", TreeItemDataType::peCliTables, previous_stream_item, nullptr)};
                        const auto *tables = pe->cli()->metadata()->metadata_tables();

                        for (auto &tt : tables->valid_table_types())
                        {
                            TreeItemDataType    type{TreeItemDataType::nothing};
                            const wchar_t      *table_name{nullptr};
                            size_t              count{0};

                            switch (tt)
                            {
                                case PeCliMetadataTableId::Assembly:
                                    table_name = L"Assembly";
                                    count = tables->assembly_table()->size();
                                    type = TreeItemDataType::peCliTableAssembly;
                                    break;
                                case PeCliMetadataTableId::AssemblyOS:
                                    table_name = L"AssemblyOS";
                                    count = tables->assembly_os_table()->size();
                                    type = TreeItemDataType::peCliTableAssemblyOS;
                                    break;
                                case PeCliMetadataTableId::AssemblyProcessor:
                                    table_name = L"AssemblyProcessor";
                                    count = tables->assembly_processor_table()->size();
                                    type = TreeItemDataType::peCliTableAssemblyProcessor;
                                    break;
                                case PeCliMetadataTableId::AssemblyRef:
                                    table_name = L"AssemblyRef";
                                    count = tables->assembly_ref_table()->size();
                                    type = TreeItemDataType::peCliTableAssemblyRef;
                                    break;
                                case PeCliMetadataTableId::AssemblyRefOS:
                                    table_name = L"AssemblyRefOS";
                                    count = tables->assembly_ref_os_table()->size();
                                    type = TreeItemDataType::peCliTableAssemblyRefOS;
                                    break;
                                case PeCliMetadataTableId::AssemblyRefProcessor:
                                    table_name = L"AssemblyRefProcessor";
                                    count = tables->assembly_ref_processor_table()->size();
                                    type = TreeItemDataType::peCliTableAssemblyRefProcessor;
                                    break;
                                case PeCliMetadataTableId::ClassLayout:
                                    table_name = L"ClassLayout";
                                    count = tables->class_layout_table()->size();
                                    type = TreeItemDataType::peCliTableClassLayout;
                                    break;
                                case PeCliMetadataTableId::Constant:
                                    table_name = L"Constant";
                                    count = tables->constant_table()->size();
                                    type = TreeItemDataType::peCliTableConstant;
                                    break;
                                case PeCliMetadataTableId::CustomAttribute:
                                    table_name = L"CustomAttribute";
                                    count = tables->custom_attribute_table()->size();
                                    type = TreeItemDataType::peCliTableCustomAttribute;
                                    break;
                                case PeCliMetadataTableId::DeclSecurity:
                                    table_name = L"DeclSecurity";
                                    count = tables->decl_security_table()->size();
                                    type = TreeItemDataType::peCliTableDeclSecurity;
                                    break;
                                case PeCliMetadataTableId::Event:
                                    table_name = L"Event";
                                    count = tables->event_table()->size();
                                    type = TreeItemDataType::peCliTableEvent;
                                    break;
                                case PeCliMetadataTableId::EventMap:
                                    table_name = L"EventMap";
                                    count = tables->event_map_table()->size();
                                    type = TreeItemDataType::peCliTableEventMap;
                                    break;
                                case PeCliMetadataTableId::ExportedType:
                                    table_name = L"ExportedType";
                                    count = tables->exported_type_table()->size();
                                    type = TreeItemDataType::peCliTableExportedType;
                                    break;
                                case PeCliMetadataTableId::Field:
                                    table_name = L"Field";
                                    count = tables->field_table()->size();
                                    type = TreeItemDataType::peCliTableField;
                                    break;
                                case PeCliMetadataTableId::FieldLayout:
                                    table_name = L"FieldLayout";
                                    count = tables->field_layout_table()->size();
                                    type = TreeItemDataType::peCliTableFieldLayout;
                                    break;
                                case PeCliMetadataTableId::FieldMarshal:
                                    table_name = L"FieldMarshal";
                                    count = tables->field_marshal_table()->size();
                                    type = TreeItemDataType::peCliTableFieldMarshal;
                                    break;
                                case PeCliMetadataTableId::FieldRVA:
                                    table_name = L"FieldRVA";
                                    count = tables->field_rva_table()->size();
                                    type = TreeItemDataType::peCliTableFieldRVA;
                                    break;
                                case PeCliMetadataTableId::File:
                                    table_name = L"File";
                                    count = tables->file_table()->size();
                                    type = TreeItemDataType::peCliTableFile;
                                    break;
                                case PeCliMetadataTableId::GenericParam:
                                    table_name = L"GenericParam";
                                    count = tables->generic_param_table()->size();
                                    type = TreeItemDataType::peCliTableGenericParam;
                                    break;
                                case PeCliMetadataTableId::GenericParamConstraint:
                                    table_name = L"GenericParamConstraint";
                                    count = tables->generic_param_constraint_table()->size();
                                    type = TreeItemDataType::peCliTableGenericParamConstraint;
                                    break;
                                case PeCliMetadataTableId::ImplMap:
                                    table_name = L"ImplMap";
                                    count = tables->impl_map_table()->size();
                                    type = TreeItemDataType::peCliTableImplMap;
                                    break;
                                case PeCliMetadataTableId::InterfaceImpl:
                                    table_name = L"InterfaceImpl";
                                    count = tables->interface_impl_table()->size();
                                    type = TreeItemDataType::peCliTableInterfaceImpl;
                                    break;
                                case PeCliMetadataTableId::ManifestResource:
                                    table_name = L"ManifestResource";
                                    count = tables->manifest_resource_table()->size();
                                    type = TreeItemDataType::peCliTableManifestResource;
                                    break;
                                case PeCliMetadataTableId::MemberRef:
                                    table_name = L"MemberRef";
                                    count = tables->member_ref_table()->size();
                                    type = TreeItemDataType::peCliTableMemberRef;
                                    break;
                                case PeCliMetadataTableId::MethodDef:
                                    table_name = L"MethodDef";
                                    count = tables->method_def_table()->size();
                                    type = TreeItemDataType::peCliTableMethodDef;
                                    break;
                                case PeCliMetadataTableId::MethodImpl:
                                    table_name = L"MethodImpl";
                                    count = tables->method_impl_table()->size();
                                    type = TreeItemDataType::peCliTableMethodImpl;
                                    break;
                                case PeCliMetadataTableId::MethodSemantics:
                                    table_name = L"MethodSemantics";
                                    count = tables->method_semantics_table()->size();
                                    type = TreeItemDataType::peCliTableMethodSemantics;
                                    break;
                                case PeCliMetadataTableId::MethodSpec:
                                    table_name = L"MethodSpec";
                                    count = tables->method_spec_table()->size();
                                    type = TreeItemDataType::peCliTableMethodSpec;
                                    break;
                                case PeCliMetadataTableId::Module:
                                    table_name = L"Module";
                                    count = tables->module_table()->size();
                                    type = TreeItemDataType::peCliTableModule;
                                    break;
                                case PeCliMetadataTableId::ModuleRef:
                                    table_name = L"ModuleRef";
                                    count = tables->module_ref_table()->size();
                                    type = TreeItemDataType::peCliTableModuleRef;
                                    break;
                                case PeCliMetadataTableId::NestedClass:
                                    table_name = L"NestedClass";
                                    count = tables->nested_class_table()->size();
                                    type = TreeItemDataType::peCliTableNestedClass;
                                    break;
                                case PeCliMetadataTableId::Param:
                                    table_name = L"Param";
                                    count = tables->param_table()->size();
                                    type = TreeItemDataType::peCliTableParam;
                                    break;
                                case PeCliMetadataTableId::Property:
                                    table_name = L"Property";
                                    count = tables->property_table()->size();
                                    type = TreeItemDataType::peCliTableProperty;
                                    break;
                                case PeCliMetadataTableId::PropertyMap:
                                    table_name = L"PropertyMap";
                                    count = tables->property_map_table()->size();
                                    type = TreeItemDataType::peCliTablePropertyMap;
                                    break;
                                case PeCliMetadataTableId::StandAloneSig:
                                    table_name = L"StandAloneSig";
                                    count = tables->standalone_sig_table()->size();
                                    type = TreeItemDataType::peCliTablePropertyMap;
                                    break;
                                case PeCliMetadataTableId::TypeDef:
                                    table_name = L"TypeDef";
                                    count = tables->type_def_table()->size();
                                    type = TreeItemDataType::peCliTableTypeDef;
                                    break;
                                case PeCliMetadataTableId::TypeRef:
                                    table_name = L"TypeRef";
                                    count = tables->type_ref_table()->size();
                                    type = TreeItemDataType::peCliTableTypeRef;
                                    break;
                                case PeCliMetadataTableId::TypeSpec:
                                    table_name = L"TypeSpec";
                                    count = tables->type_spec_table()->size();
                                    type = TreeItemDataType::peCliTableTypeSpec;
                                    break;
                            }

                            if (table_name)
                            {
                                StringCbPrintf(name_buffer.data(), name_buffer.size(), L"%02X %s (%I64u)", static_cast<uint8_t>(tt), table_name, count);
                                _main_tree.add_item(name_buffer.data(), type, pe_cli_tables, nullptr);
                            }
                        }
                    }
                }
            }

            _main_tree.expand(item_pe_cli, TVE_EXPAND);
        }
        //TODO: Do more here!!!
    }

    _main_tree.select(item_root, TVGN_CARET);
}

void MainWindow::set_file_info(LPCTSTR path)
{
    _file_info.path = path;

    _file_info.access_time.dwHighDateTime = _file_info.access_time.dwLowDateTime = 0;
    _file_info.write_time = _file_info.create_time = _file_info.access_time;
    _file_info.size.QuadPart = 0;

    HANDLE  fh = CreateFile(path,
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            NULL,
                            OPEN_EXISTING,
                            0,
                            NULL);
    if (fh != INVALID_HANDLE_VALUE)
    {
        BY_HANDLE_FILE_INFORMATION info;
        if (GetFileInformationByHandle(fh, &info))
        {
            _file_info.create_time = info.ftCreationTime;
            _file_info.access_time = info.ftLastAccessTime;
            _file_info.write_time = info.ftLastWriteTime;
            _file_info.size.HighPart = info.nFileSizeHigh;
            _file_info.size.LowPart = info.nFileSizeLow;
        }
        CloseHandle(fh);
    }
    //TODO: Add more!!!
}
