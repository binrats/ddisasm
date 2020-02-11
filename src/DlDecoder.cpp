//===- DlDecoder.cpp --------------------------------------------*- C++ -*-===//
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

#include "DlDecoder.h"
#include <souffle/CompiledSouffle.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include "BinaryReader.h"
#include "ExceptionDecoder.h"
#include "GtirbZeroBuilder.h"

namespace souffle
{
    template <class T>
    souffle::tuple &operator<<(souffle::tuple &t, const DlData<T> &data)
    {
        t << data.ea << data.content;
        return t;
    }

    souffle::tuple &operator<<(souffle::tuple &t, const InitialAuxData::Relocation &relocation)
    {
        t << relocation.address << relocation.type << relocation.name << relocation.addend;
        return t;
    }

    souffle::tuple &operator<<(souffle::tuple &t, const InitialAuxData::Symbol &symbol)
    {
        t << symbol.address << symbol.size << symbol.type << symbol.scope << symbol.sectionIndex
          << symbol.name;
        return t;
    }

} // namespace souffle

std::string getFileFormatString(gtirb::FileFormat format)
{
    switch(format)
    {
        case gtirb::FileFormat::COFF:
            return "COFF";
        case gtirb::FileFormat::ELF:
            return "ELF";
        case gtirb::FileFormat::PE:
            return "PE";
        case gtirb::FileFormat::IdaProDb32:
            return "IdaProDb32";
        case gtirb::FileFormat::IdaProDb64:
            return "IdaProDb64";
        case gtirb::FileFormat::XCOFF:
            return "XCOFF";
        case gtirb::FileFormat::MACHO:
            return "MACHO";
        case gtirb::FileFormat::RAW:
            return "RAW";
        case gtirb::FileFormat::Undefined:
        default:
            return "Undefined";
    }
}

void addSymbols(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    auto *rel = prog->getRelation("symbol");
    auto *extraInfoTable =
        module.getAuxData<std::map<gtirb::UUID, ExtraSymbolInfo>>("extraSymbolInfo");
    for(auto &symbol : module.symbols())
    {
        souffle::tuple t(rel);
        if(auto address = symbol.getAddress())
            t << *address;
        else
            t << 0;
        auto found = extraInfoTable->find(symbol.getUUID());
        if(found == extraInfoTable->end())
            throw std::logic_error("Symbol " + symbol.getName()
                                   + " missing from extraSymbolInfo AuxData table");

        ExtraSymbolInfo &extraInfo = found->second;
        t << extraInfo.size << extraInfo.type << extraInfo.scope << extraInfo.sectionIndex
          << symbol.getName();
        rel->insert(t);
    }
}

void addSections(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    auto *rel = prog->getRelation("section_complete");
    auto *extraInfoTable =
        module.getAuxData<std::map<gtirb::UUID, SectionProperties>>("elfSectionProperties");
    if(!extraInfoTable)
        throw std::logic_error("missing elfSectionProperties AuxData table");

    for(auto &section : module.sections())
    {
        souffle::tuple t(rel);
        auto found = extraInfoTable->find(section.getUUID());
        if(found == extraInfoTable->end())
            throw std::logic_error("Section " + section.getName()
                                   + " missing from elfSectionProperties AuxData table");
        SectionProperties &extraInfo = found->second;
        t << section.getName() << section.getSize() << section.getAddress()
          << std::get<0>(extraInfo) << std::get<1>(extraInfo);
        rel->insert(t);
    }
}

/*
DlDecoder::DlDecoder()
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle); // == CS_ERR_OK
    cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

DlDecoder::~DlDecoder()
{
    cs_close(&this->csHandle);
}*/

souffle::SouffleProgram *DlDecoder::decode(gtirb::Module &module)
{
    auto minMax = module.getImageByteMap().getAddrMinMax();
    auto *extraInfoTable =
        module.getAuxData<std::map<gtirb::UUID, SectionProperties>>("elfSectionProperties");
    if(!extraInfoTable)
        throw std::logic_error("missing elfSectionProperties AuxData table");
    for(auto &section : module.sections())
    {
        auto found = extraInfoTable->find(section.getUUID());
        if(found == extraInfoTable->end())
            throw std::logic_error("Section " + section.getName()
                                   + " missing from elfSectionProperties AuxData table");
        SectionProperties &extraInfo = found->second;
        if(isExeSection(extraInfo))
        {
            gtirb::ImageByteMap::const_range bytes =
                gtirb::getBytes(module.getImageByteMap(), section);
            decodeSection(bytes, bytes.size(), section.getAddress());
            storeDataSection(bytes, bytes.size(), section.getAddress(), minMax.first,
                             minMax.second);
        }
        if(isNonZeroDataSection(extraInfo))
        {
            gtirb::ImageByteMap::const_range bytes =
                gtirb::getBytes(module.getImageByteMap(), section);
            storeDataSection(bytes, bytes.size(), section.getAddress(), minMax.first,
                             minMax.second);
        }
    }
    if(auto prog = souffle::ProgramFactory::newInstance("souffle_disasm"))
    {
        loadInputs(prog, module);
        return prog;
    }
    return nullptr;
}

void DlDecoder::storeDataSection(gtirb::ImageByteMap::const_range &sectionBytes, uint64_t size,
                                 gtirb::Addr ea, gtirb::Addr min_address, gtirb::Addr max_address)
{
    auto can_be_address = [min_address, max_address](gtirb::Addr num) {
        return ((num >= min_address) && (num <= max_address));
    };
    auto buf = reinterpret_cast<const uint8_t *>(&*sectionBytes.begin());
    while(size > 0)
    {
        // store the byte
        uint8_t content_byte = *buf;
        data_bytes.push_back({ea, content_byte});

        // store the address
        if(size >= 8)
        {
            gtirb::Addr content(*((int64_t *)buf));
            if(can_be_address(content))
                data_addresses.push_back({ea, content});
        }
        ++ea;
        ++buf;
        --size;
    }
}

void DlDecoder::loadInputs(souffle::SouffleProgram *prog, gtirb::Module &module)
{
    GtirbToDatalog::addToRelation<std::vector<std::string>>(
        prog, "binary_type", *module.getAuxData<std::vector<std::string>>("binaryType"));
    GtirbToDatalog::addToRelation<std::vector<std::string>>(
        prog, "binary_format", {getFileFormatString(module.getFileFormat())});
    gtirb::ImageByteMap &byteMap = module.getImageByteMap();
    GtirbToDatalog::addToRelation<std::vector<gtirb::Addr>>(prog, "entry_point",
                                                            {byteMap.getEntryPointAddress()});
    GtirbToDatalog::addToRelation(
        prog, "relocation",
        *module.getAuxData<std::set<InitialAuxData::Relocation>>("relocations"));
    module.removeAuxData("relocations");

    GtirbToDatalog::addToRelation(prog, "instruction_complete", instructions);
    GtirbToDatalog::addToRelation(prog, "address_in_data", data_addresses);
    GtirbToDatalog::addToRelation(prog, "data_byte", data_bytes);
    GtirbToDatalog::addToRelation(prog, "invalid_op_code", invalids);
    GtirbToDatalog::addToRelation(prog, "op_regdirect", op_dict.regTable);
    GtirbToDatalog::addToRelation(prog, "op_immediate", op_dict.immTable);
    GtirbToDatalog::addToRelation(prog, "op_indirect", op_dict.indirectTable);
    addSymbols(prog, module);
    module.removeAuxData("extraSymbolInfo");
    addSections(prog, module);
    ExceptionDecoder excDecoder(module);
    excDecoder.addExceptionInformation(prog);
}
