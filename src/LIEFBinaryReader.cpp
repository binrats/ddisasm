//===- LIEFBinaryReader.cpp ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#include "LIEFBinaryReader.h"
#include <cassert>

LIEFBinaryReader::LIEFBinaryReader(const std::string& filename)
{
    bin = LIEF::Parser::parse(filename);
}

bool LIEFBinaryReader::is_valid()
{
    return bin->format() == LIEF::EXE_FORMATS::FORMAT_ELF;
}


std::tuple<LIEF::ARCHITECTURES, LIEF::ENDIANNESS> LIEFBinaryReader::get_container_info() {
    LIEF::Header header = this->bin->header();
    return std::make_tuple(header.architecture(), header.endianness());
}


std::optional<std::tuple<std::vector<uint8_t>, uint64_t>>
LIEFBinaryReader::get_section_content_and_address(const std::string& name)
{
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& section : elf->sections())
        {
            if(section.name() == name && section.type() != LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS)
                return std::make_tuple(section.content(), section.virtual_address());
        }
    }
    return std::nullopt;
}

uint64_t LIEFBinaryReader::get_max_address()
{
    uint64_t max_address = 0;
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& section : elf->sections())
        {
            if(section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS
               || section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS)
            {
                max_address = std::max(max_address, section.virtual_address() + section.size());
            }
        }
    }

    return max_address;
}

uint64_t LIEFBinaryReader::get_min_address()
{
    uint64_t min_address = UINTMAX_MAX;
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& section : elf->sections())
        {
            if(section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS
               || section.type() == LIEF::ELF::ELF_SECTION_TYPES::SHT_NOBITS)
            {
                min_address = std::min(min_address, section.virtual_address());
            }
        }
    }
    return min_address;
}

std::set<InitialAuxData::Section> LIEFBinaryReader::get_sections()
{
    std::set<InitialAuxData::Section> sectionTuples;
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& section : elf->sections())
        {
            if(section.flags_list().count(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC))
                sectionTuples.insert({section.name(), section.size(), section.virtual_address(),
                                      static_cast<uint64_t>(section.type()),
                                      static_cast<uint64_t>(section.flags())});
        }
    }

    return sectionTuples;
}

gtirb::FileFormat LIEFBinaryReader::get_binary_format()
{
    if(bin->format() == LIEF::EXE_FORMATS::FORMAT_ELF)
        return gtirb::FileFormat::ELF;
    return gtirb::FileFormat::Undefined;
}

std::string LIEFBinaryReader::get_binary_type()
{
    if(bin->format() == LIEF::EXE_FORMATS::FORMAT_ELF && bin->is_pie())
        return "DYN";
    return "EXEC";
}

uint64_t LIEFBinaryReader::get_entry_point()
{
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
        return elf->entrypoint();
    return 0;
}

std::set<InitialAuxData::Symbol> LIEFBinaryReader::get_symbols()
{
    std::set<InitialAuxData::Symbol> symbolTuples;
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& symbol : elf->symbols())
        {
            std::string symbolName = symbol.name();
            std::size_t foundVersion = symbolName.find('@');
            if(foundVersion != std::string::npos)
                symbolName = symbolName.substr(0, foundVersion);
            if(symbol.type() != LIEF::ELF::ELF_SYMBOL_TYPES::STT_SECTION)
                symbolTuples.insert(
                    {symbol.value(), symbol.size(), LIEF::ELF::to_string(symbol.type()),
                     LIEF::ELF::to_string(symbol.binding()), symbol.section_idx(), symbolName});
        }
    }

    return symbolTuples;
}

std::set<InitialAuxData::Relocation> LIEFBinaryReader::get_relocations()
{
    std::set<InitialAuxData::Relocation> relocationTuples;
    if(auto* elf = dynamic_cast<LIEF::ELF::Binary*>(bin.get()))
    {
        for(auto& relocation : elf->relocations())
        {
            relocationTuples.insert({relocation.address(), getRelocationType(relocation),
                                     relocation.symbol().name(), relocation.addend()});
        }
    }
    return relocationTuples;
}

std::vector<std::string> LIEFBinaryReader::get_libraries()
{
    std::vector<std::string> libraries;
    // TODO
    return libraries;
}

std::vector<std::string> LIEFBinaryReader::get_library_paths()
{
    std::vector<std::string> libraryPaths;
    // TODO
    return libraryPaths;
}

std::string LIEFBinaryReader::getRelocationType(const LIEF::ELF::Relocation& entry)
{
    switch(entry.architecture())
    {
        case LIEF::ELF::ARCH::EM_X86_64:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_x86_64>(entry.type()));
        case LIEF::ELF::ARCH::EM_386:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_i386>(entry.type()));
        case LIEF::ELF::ARCH::EM_ARM:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_ARM>(entry.type()));
        case LIEF::ELF::ARCH::EM_AARCH64:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_AARCH64>(entry.type()));
        case LIEF::ELF::ARCH::EM_PPC:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_POWERPC32>(entry.type()));
        case LIEF::ELF::ARCH::EM_PPC64:
            return LIEF::ELF::to_string(static_cast<LIEF::ELF::RELOC_POWERPC64>(entry.type()));
        default:
            return std::to_string(entry.type());
    }
}
