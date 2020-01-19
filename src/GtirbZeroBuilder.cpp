//===- GtirbZeroBuilder.cpp -------------------------------------*- C++ -*-===//
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

#include "GtirbZeroBuilder.h"
#include "BinaryReader.h"
#include "LIEFBinaryReader.h"

bool isExeSection(const SectionProperties &s)
{
    uint64_t flags = std::get<1>(s);
    return flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
};

bool isNonZeroDataSection(const SectionProperties &s)
{
    uint64_t type = std::get<0>(s);
    uint64_t flags = std::get<1>(s);

    bool is_allocated = flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC);
    bool is_not_executable =
        !(flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR));
    // SHT_NOBITS is not considered here because it is for data sections but without initial
    // data (zero initialized)
    bool is_non_zero_program_data =
        type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PROGBITS)
        || type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_INIT_ARRAY)
        || type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_FINI_ARRAY)
        || type == static_cast<int>(LIEF::ELF::ELF_SECTION_TYPES::SHT_PREINIT_ARRAY);
    return is_allocated && is_not_executable && is_non_zero_program_data;
};

bool isAllocatedSection(int flags)
{
    return (flags & static_cast<int>(LIEF::ELF::ELF_SECTION_FLAGS::SHF_ALLOC));
}

std::string gtirb::auxdata_traits<ExtraSymbolInfo>::type_id()
{
    return "ExtraSymbolInfo";
}

void gtirb::auxdata_traits<ExtraSymbolInfo>::toBytes(const ExtraSymbolInfo &Object, to_iterator It)
{
    auxdata_traits<uint64_t>::toBytes(Object.size, It);
    auxdata_traits<std::string>::toBytes(Object.type, It);
    auxdata_traits<std::string>::toBytes(Object.scope, It);
    auxdata_traits<uint64_t>::toBytes(Object.sectionIndex, It);
}

gtirb::from_iterator gtirb::auxdata_traits<ExtraSymbolInfo>::fromBytes(ExtraSymbolInfo &Object,
                                                                       from_iterator It)
{
    It = auxdata_traits<uint64_t>::fromBytes(Object.size, It);
    It = auxdata_traits<std::string>::fromBytes(Object.type, It);
    It = auxdata_traits<std::string>::fromBytes(Object.scope, It);
    It = auxdata_traits<uint64_t>::fromBytes(Object.sectionIndex, It);
    return It;
}

void buildByteMap(gtirb::Module &module, std::shared_ptr<BinaryReader> binary)
{
    auto &byteMap = module.getImageByteMap();
    byteMap.setAddrMinMax(
        {gtirb::Addr(binary->get_min_address()), gtirb::Addr(binary->get_max_address())});
    byteMap.setEntryPointAddress(gtirb::Addr(binary->get_entry_point()));
    std::map<gtirb::UUID, SectionProperties> sectionProperties;
    for(auto &binSection : binary->get_sections())
    {
        if(isAllocatedSection(binSection.flags))
        {
            if(auto sectionData = binary->get_section_content_and_address(binSection.name))
            {
                std::vector<uint8_t> &sectionBytes = std::get<0>(*sectionData);
                std::byte *begin = reinterpret_cast<std::byte *>(sectionBytes.data());
                std::byte *end =
                    reinterpret_cast<std::byte *>(sectionBytes.data() + sectionBytes.size());
                byteMap.setData(gtirb::Addr(binSection.address),
                                boost::make_iterator_range(begin, end));
            }
        }
    }
}

void buildSections(gtirb::Module &module, std::shared_ptr<BinaryReader> binary,
                   gtirb::Context &context)
{
    std::map<gtirb::UUID, SectionProperties> sectionProperties;
    for(auto &binSection : binary->get_sections())
    {
        if(isAllocatedSection(binSection.flags))
        {
            gtirb::Section *section = gtirb::Section::Create(
                context, binSection.name, gtirb::Addr(binSection.address), binSection.size);
            module.addSection(section);
            sectionProperties[section->getUUID()] =
                std::make_tuple(binSection.type, binSection.flags);
        }
    }
    module.addAuxData("elfSectionProperties", std::move(sectionProperties));
}

gtirb::Symbol::StorageKind getSymbolType(uint64_t sectionIndex, std::string scope)
{
    if(sectionIndex == 0)
        return gtirb::Symbol::StorageKind::Undefined;
    if(scope == "GLOBAL")
        return gtirb::Symbol::StorageKind::Normal;
    if(scope == "LOCAL")
        return gtirb::Symbol::StorageKind::Local;
    return gtirb::Symbol::StorageKind::Extern;
}

void buildSymbols(gtirb::Module &module, std::shared_ptr<BinaryReader> binary,
                  gtirb::Context &context)
{
    std::map<gtirb::UUID, ExtraSymbolInfo> extraSymbolInfoTable;
    for(auto &binSymbol : binary->get_symbols())
    {
        // Symbols with special section index do not have an address
        gtirb::Symbol *symbol;
        if(binSymbol.sectionIndex == static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_UNDEF)
           || (binSymbol.sectionIndex
                   >= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_LORESERVE)
               && binSymbol.sectionIndex
                      <= static_cast<int>(LIEF::ELF::SYMBOL_SECTION_INDEX::SHN_HIRESERVE)))
            symbol = gtirb::emplaceSymbol(module, context, binSymbol.name);
        else
            symbol = gtirb::emplaceSymbol(module, context, gtirb::Addr(binSymbol.address),
                                          binSymbol.name,
                                          getSymbolType(binSymbol.sectionIndex, binSymbol.scope));
        extraSymbolInfoTable[symbol->getUUID()] = {binSymbol.size, binSymbol.type, binSymbol.scope,
                                                   binSymbol.sectionIndex};
    }
    module.addAuxData("extraSymbolInfo", std::move(extraSymbolInfoTable));
}
void addAuxiliaryTables(gtirb::Module &module, std::shared_ptr<BinaryReader> binary)
{
    std::vector<std::string> binaryType = {binary->get_binary_type()};
    module.addAuxData("binaryType", binaryType);
    module.addAuxData("relocations", binary->get_relocations());
    module.addAuxData("libraries", binary->get_libraries());
    module.addAuxData("libraryPaths", binary->get_library_paths());
}

std::tuple<gtirb::IR*, LIEF::ARCHITECTURES, LIEF::ENDIANNESS> buildZeroIR(const std::string &filename, gtirb::Context &context)
{
    std::shared_ptr<BinaryReader> binary(new LIEFBinaryReader(filename));
    LIEF::ARCHITECTURES arch;
    LIEF::ENDIANNESS endianness;
    std::tie(arch, endianness) = binary->get_container_info();

    if(!binary->is_valid())
        return std::make_tuple(nullptr, LIEF::ARCHITECTURES::ARCH_NONE, LIEF::ENDIANNESS::ENDIAN_NONE);
    auto ir = gtirb::IR::Create(context);
    gtirb::Module &module = *gtirb::Module::Create(context);
    module.setBinaryPath(filename);
    module.setFileFormat(binary->get_binary_format());
    module.setISAID(gtirb::ISAID::X64);
    ir->addModule(&module);
    buildByteMap(module, binary);
    buildSections(module, binary, context);
    buildSymbols(module, binary, context);
    addAuxiliaryTables(module, binary);

    return std::make_tuple(ir, arch, endianness);
}
