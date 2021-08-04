/// \file   fntextract.cpp
/// The source file for the fntextract sample.
/// 
/// \author Jeff Bienstadt
///

#include <exception>
#include <fstream>
#include <iostream>

#include <ExeInfo.h>
#include <resource_type.h>

void save_resource(const std::string &name, const NeExeInfo::ByteContainer &content)
{
    std::string     filename = "fnt_" + name + ".fnt";
    // Open a file for writing. If the file exists, we over-write it.
    std::ofstream   fs(filename, std::ios::binary | std::ios::trunc);

    if (fs.is_open())
    {
        fs.write(reinterpret_cast<const char *>(content.data()), content.size());
        std::cout << "Wrote " << filename << std::endl;
    }
    else
    {
        throw std::runtime_error("Failed to open file " + filename);
    }
}

size_t process_resources(const NeExeInfo::ResourceContainer &resources)
{
    size_t  font_count = 0;

    for (const auto &resource : resources)
    {
        if (resource.type & 0x8000) // if the high bit of the type is set, type is an integer
        {
            if ((resource.type & ~0x8000) == static_cast<uint16_t>(ResourceType::Font))
            {
                for (const auto &info : resource.info)
                {
                    if (info.id & 0x8000)   // if the high bit of the id is set, construct a name from the integer
                        save_resource('#' + std::to_string(info.id & ~0x8000), info.bits);
                    else
                        save_resource(info.name, info.bits);
                    ++font_count;
                }
            }
        }
    }

    return font_count;
}

void process_file(const char *path)
{
    std::ifstream   fs(path, std::ios::in | std::ios::binary);

    if (fs.is_open())
    {
        ExeInfo exeInfo(fs);    // Open and load the executable file. ExeInfo is the core object of the library.
        auto    ne = exeInfo.ne_part();
        if (ne == nullptr)
            throw std::runtime_error("This doesn't look like a .fon file! It's ot an NE executable file");

        auto    count = process_resources(ne->resource_table());
        std::cout << "Saved " << count << " fonts.\n";
    }
    else
    {
        std::string msg{"Could not open file "};
        msg += path;

        throw std::runtime_error(msg);
    }
}

void usage()
{
    std::cerr << "Usage: exedump <filename> [<filename>...]\n";
}

int main(int argc, char **argv)
{
    if (argc == 2)
    {
        try
        {
            process_file(argv[1]);
            return 0;
        }
        catch (const std::exception &ex)
        {
            std::cerr << ex.what() << '\n';
            return 1;
        }
    }
    else
    {
        usage();
        return 1;
    }
}