// This ruleset is used for unit tests - Modification will require test updates

import "elf"

rule elf_001
{
    condition:
        elf.number_of_sections == 1
}

rule elf_002
{
    condition:
        elf.machine == elf.EM_X86_64
}
