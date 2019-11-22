// Copyright 2014 Renato Tegon Forti, Antony Polukhin.
// Copyright 2015-2019 Antony Polukhin.
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt
// or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_DLL_DETAIL_POSIX_ELF_INFO_HPP
#define BOOST_DLL_DETAIL_POSIX_ELF_INFO_HPP

#include <boost/dll/config.hpp>

#ifdef BOOST_HAS_PRAGMA_ONCE
# pragma once
#endif

#include <cstring>
#include <fstream>

#include <boost/cstdint.hpp>

namespace boost { namespace dll { namespace detail {

template <class AddressOffsetT>
struct Elf_Ehdr_template {
  unsigned char     e_ident[16];    /* Magic number and other info */
  boost::uint16_t   e_type;         /* Object file type */
  boost::uint16_t   e_machine;      /* Architecture */
  boost::uint32_t   e_version;      /* Object file version */
  AddressOffsetT    e_entry;        /* Entry point virtual address */
  AddressOffsetT    e_phoff;        /* Program header table file offset */
  AddressOffsetT    e_shoff;        /* Section header table file offset */
  boost::uint32_t   e_flags;        /* Processor-specific flags */
  boost::uint16_t   e_ehsize;       /* ELF header size in bytes */
  boost::uint16_t   e_phentsize;    /* Program header table entry size */
  boost::uint16_t   e_phnum;        /* Program header table entry count */
  boost::uint16_t   e_shentsize;    /* Section header table entry size */
  boost::uint16_t   e_shnum;        /* Section header table entry count */
  boost::uint16_t   e_shstrndx;     /* Section header string table index */
};

typedef Elf_Ehdr_template<boost::uint32_t> Elf32_Ehdr_;
typedef Elf_Ehdr_template<boost::uint64_t> Elf64_Ehdr_;

template <class AddressOffsetT>
struct Elf_Shdr_template {
  boost::uint32_t   sh_name;        /* Section name (string tbl index) */
  boost::uint32_t   sh_type;        /* Section type */
  AddressOffsetT    sh_flags;       /* Section flags */
  AddressOffsetT    sh_addr;        /* Section virtual addr at execution */
  AddressOffsetT    sh_offset;      /* Section file offset */
  AddressOffsetT    sh_size;        /* Section size in bytes */
  boost::uint32_t   sh_link;        /* Link to another section */
  boost::uint32_t   sh_info;        /* Additional section information */
  AddressOffsetT    sh_addralign;   /* Section alignment */
  AddressOffsetT    sh_entsize;     /* Entry size if section holds table */
};

typedef Elf_Shdr_template<boost::uint32_t> Elf32_Shdr_;
typedef Elf_Shdr_template<boost::uint64_t> Elf64_Shdr_;

template <class AddressOffsetT>
struct Elf_Sym_template;

template <>
struct Elf_Sym_template<boost::uint32_t> {
  typedef boost::uint32_t AddressOffsetT;

  boost::uint32_t   st_name;    /* Symbol name (string tbl index) */
  AddressOffsetT    st_value;   /* Symbol value */
  AddressOffsetT    st_size;    /* Symbol size */
  unsigned char     st_info;    /* Symbol type and binding */
  unsigned char     st_other;   /* Symbol visibility */
  boost::uint16_t   st_shndx;   /* Section index */
};

template <>
struct Elf_Sym_template<boost::uint64_t> {
  typedef boost::uint64_t AddressOffsetT;

  boost::uint32_t   st_name;    /* Symbol name (string tbl index) */
  unsigned char     st_info;    /* Symbol type and binding */
  unsigned char     st_other;   /* Symbol visibility */
  boost::uint16_t   st_shndx;   /* Section index */
  AddressOffsetT    st_value;   /* Symbol value */
  AddressOffsetT    st_size;    /* Symbol size */
};


typedef Elf_Sym_template<boost::uint32_t> Elf32_Sym_;
typedef Elf_Sym_template<boost::uint64_t> Elf64_Sym_;

template <class AddressOffsetT>
class elf_info {
    typedef boost::dll::detail::Elf_Ehdr_template<AddressOffsetT>  header_t;
    typedef boost::dll::detail::Elf_Shdr_template<AddressOffsetT>  section_t;
    typedef boost::dll::detail::Elf_Sym_template<AddressOffsetT>   symbol_t;

    BOOST_STATIC_CONSTANT(boost::uint32_t, SHT_SYMTAB_ = 2);
    BOOST_STATIC_CONSTANT(boost::uint32_t, SHT_STRTAB_ = 3);

    BOOST_STATIC_CONSTANT(unsigned char, STB_LOCAL_ = 0);   /* Local symbol */
    BOOST_STATIC_CONSTANT(unsigned char, STB_GLOBAL_ = 1);  /* Global symbol */
    BOOST_STATIC_CONSTANT(unsigned char, STB_WEAK_ = 2);    /* Weak symbol */

    /* Symbol visibility specification encoded in the st_other field.  */
    BOOST_STATIC_CONSTANT(unsigned char, STV_DEFAULT_ = 0);      /* Default symbol visibility rules */
    BOOST_STATIC_CONSTANT(unsigned char, STV_INTERNAL_ = 1);     /* Processor specific hidden class */
    BOOST_STATIC_CONSTANT(unsigned char, STV_HIDDEN_ = 2);       /* Sym unavailable in other modules */
    BOOST_STATIC_CONSTANT(unsigned char, STV_PROTECTED_ = 3);    /* Not preemptible, not exported */

public:
    static bool parsing_supported(std::ifstream& f) {
        const unsigned char magic_bytes[5] = { 
            0x7f, 'E', 'L', 'F', sizeof(boost::uint32_t) == sizeof(AddressOffsetT) ? 1 : 2
        };

        unsigned char ch;
        f.seekg(0);
        for (std::size_t i = 0; i < sizeof(magic_bytes); ++i) {
            f >> ch;
            if (ch != magic_bytes[i]) {
                return false;
            }
        }

        return true;
    }

    static std::vector<std::string> sections(std::ifstream& f) {
        std::vector<std::string> ret;
        std::vector<char> names;
        sections_names_raw(f, names);
        
        const char* name_begin = &names[0];
        const char* const name_end = name_begin + names.size();
        ret.reserve(header(f).e_shnum);
        do {
            ret.push_back(name_begin);
            name_begin += ret.back().size() + 1;
        } while (name_begin != name_end);

        return ret;
    }

private:
    template <class T>
    static void read_raw(std::ifstream& f, T& value, std::size_t size = sizeof(T)) {
        f.read(reinterpret_cast<char*>(&value), size);
    }

    static header_t header(std::ifstream& f) {
        header_t elf;

        f.seekg(0);
        read_raw(f, elf);

        return elf;
    }

    static void sections_names_raw(std::ifstream& f, std::vector<char>& sections) {
        const header_t elf = header(f);

        section_t section_names_section;
        f.seekg(elf.e_shoff + elf.e_shstrndx * sizeof(section_t));
        read_raw(f, section_names_section);

        sections.resize(static_cast<std::size_t>(section_names_section.sh_size));
        f.seekg(section_names_section.sh_offset);
        read_raw(f, sections[0], static_cast<std::size_t>(section_names_section.sh_size));
    }

    static void symbols_text(std::ifstream& f, std::vector<symbol_t>& symbols, std::vector<char>& text) {
        const header_t elf = header(f);
        f.seekg(elf.e_shoff);

        for (std::size_t i = 0; i < elf.e_shnum; ++i) {
            section_t section;
            read_raw(f, section);

            if (section.sh_type == SHT_SYMTAB_) {
                symbols.resize(static_cast<std::size_t>(section.sh_size / sizeof(symbol_t)));

                const std::ifstream::pos_type pos = f.tellg();
                f.seekg(section.sh_offset);
                read_raw(f, symbols[0], static_cast<std::size_t>(section.sh_size - (section.sh_size % sizeof(symbol_t))) );
                f.seekg(pos);
            } else if (section.sh_type == SHT_STRTAB_) {
                text.resize(static_cast<std::size_t>(section.sh_size));

                const std::ifstream::pos_type pos = f.tellg();
                f.seekg(section.sh_offset);
                read_raw(f, text[0], static_cast<std::size_t>(section.sh_size));
                f.seekg(pos);
            }
        }
    }

    static bool is_visible(const symbol_t& sym) BOOST_NOEXCEPT {
        // `(sym.st_info >> 4) != STB_LOCAL_ && !!sym.st_size` check also workarounds the
        // GCC's issue https://sourceware.org/bugzilla/show_bug.cgi?id=13621
        return (sym.st_other & 0x03) == STV_DEFAULT_ && (sym.st_info >> 4) != STB_LOCAL_ && !!sym.st_size;
    }

public:
    static std::vector<std::string> symbols(std::ifstream& f) {
        std::vector<std::string> ret;

        std::vector<symbol_t> symbols;
        std::vector<char>   text;
        symbols_text(f, symbols, text);

        ret.reserve(symbols.size());
        for (std::size_t i = 0; i < symbols.size(); ++i) {
            if (is_visible(symbols[i])) {
                ret.push_back(&text[0] + symbols[i].st_name);
                if (ret.back().empty()) {
                    ret.pop_back(); // Do not show empty names
                }
            }
        }

        return ret;
    }

    static std::vector<std::string> symbols(std::ifstream& f, const char* section_name) {
        std::vector<std::string> ret;
        
        std::size_t index = 0;
        std::size_t ptrs_in_section_count = 0;
        {
            std::vector<char> names;
            sections_names_raw(f, names);

            const header_t elf = header(f);

            for (; index < elf.e_shnum; ++index) {
                section_t section;
                f.seekg(elf.e_shoff + index * sizeof(section_t));
                read_raw(f, section);
            
                if (!std::strcmp(&names[0] + section.sh_name, section_name)) {
                    if (!section.sh_entsize) {
                        section.sh_entsize = 1;
                    }
                    ptrs_in_section_count = static_cast<std::size_t>(section.sh_size / section.sh_entsize);
                    break;
                }
            }                        
        }

        std::vector<symbol_t> symbols;
        std::vector<char>   text;
        symbols_text(f, symbols, text);
    
        if (ptrs_in_section_count < symbols.size()) {
            ret.reserve(ptrs_in_section_count);
        } else {
            ret.reserve(symbols.size());
        }

        for (std::size_t i = 0; i < symbols.size(); ++i) {
            if (symbols[i].st_shndx == index && is_visible(symbols[i])) {
                ret.push_back(&text[0] + symbols[i].st_name);
                if (ret.back().empty()) {
                    ret.pop_back(); // Do not show empty names
                }
            }
        }

        return ret;
    }
};

typedef elf_info<boost::uint32_t> elf_info32;
typedef elf_info<boost::uint64_t> elf_info64;

}}} // namespace boost::dll::detail

#endif // BOOST_DLL_DETAIL_POSIX_ELF_INFO_HPP
