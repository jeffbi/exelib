#ifndef _FILE_INFO_H_
#define _FILE_INFO_H_

#include <string>

struct FileInfo
{
    std::wstring    path;
    //TODO: Add more info about the file!!!
    FILETIME        create_time{0};
    FILETIME        access_time{0};
    FILETIME        write_time{0};
    LARGE_INTEGER   size{0};
};

#endif  // _FILE_INFO_H_
