#include "X86Decoder.h"
#include <souffle/CompiledSouffle.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include "BinaryReader.h"
#include "ExceptionDecoder.h"
#include "GtirbZeroBuilder.h"


X86Decoder::X86Decoder()
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle); // == CS_ERR_OK
    cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

X86Decoder::~X86Decoder()
{
    cs_close(&this->csHandle);
}

souffle::SouffleProgram* X86Decoder::decode(gtirb::Module &module)
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
    if(auto prog = souffle::ProgramFactory::newInstance("souffle_disasm_x64"))
    {
        loadInputs(prog, module);
        return prog;
    }
    return nullptr;
}


void X86Decoder::decodeSection(gtirb::ImageByteMap::const_range &sectionBytes, uint64_t size,
                              gtirb::Addr ea)
{
    auto buf = reinterpret_cast<const uint8_t *>(&*sectionBytes.begin());
    while(size > 0)
    {
        cs_insn *insn;
        size_t count = cs_disasm(csHandle, buf, size, static_cast<uint64_t>(ea), 1, &insn);
        if(count == 0)
        {
            invalids.push_back(ea);
        }
        else
        {
            instructions.push_back(GtirbToDatalog::transformInstruction(CS_ARCH_X86, csHandle, op_dict, *insn));
            cs_free(insn, count);
        }
        ++ea;
        ++buf;
        --size;
    }
}


