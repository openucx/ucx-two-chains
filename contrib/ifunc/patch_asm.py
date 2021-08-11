#!/usr/bin/env python3
#
# Copyright (C) ARM Ltd. 2016-2021.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#
# Modify assembly for use as ifunc code segments

import re
import sys


# Just make anything with a type global
def fix_globals(line):
    ret = []    # We may change one line into two lines, so use a list
    m = re.match("^\s*\.type\s+(.+),.+$", line)
    if m is not None:
        ret.append("    .global {}".format(m.group(1)))
    ret.append(line)
    return ret


if len(sys.argv) != 2:
    print("Usage: {} ifunc_name < input.s > output.s".format(sys.argv[0]))
    sys.exit(1)

ifname = sys.argv[1]

# Section types
sec_other  = 0
sec_text   = 1
sec_data   = 2
sec_rodata = 3

# Which type of section are we currently in?
in_sec     = 0

# Store the content of each type of section
s_other    = []
s_text     = []
s_data     = []
s_rodata   = []
s_data_n   = 0
s_rodata_n = 0


# Process the input file
for line in sys.stdin:
    line = line.replace('\n', '')   # Python being 'smart'
    if re.match("^\s*\.text\s*$", line) is not None:
        # Find text sections
        in_sec = sec_text
    elif re.match("^\s*\.data\s*$", line) is not None:
        # Find and label data sections
        in_sec = sec_data
        s_data.append("    .global {}_data_{}".format(ifname, s_data_n))
        s_data.append("{}_data_{}:".format(ifname, s_data_n))
        s_data_n += 1
    elif re.match("^\s*\.section\s+\.rodata.*$", line) is not None:
        # Find and label rodata sections
        in_sec = sec_rodata
        s_rodata.append("    .global {}_rodata_{}".format(ifname, s_rodata_n))
        s_rodata.append("{}_rodata_{}:".format(ifname, s_rodata_n))
        s_rodata_n += 1
    elif re.match("^\s*\.global\s+.*$", line) is not None:
        # Ignore global defs that are outside section
        continue
    elif re.match("^\s*\.section\s*.*$", line) is not None:
        in_sec = sec_other
        s_other.append(line)
    elif in_sec == sec_other:
        s_other += fix_globals(line)
    elif in_sec == sec_text:
        s_text += fix_globals(line)
    elif in_sec == sec_data:
        s_data += fix_globals(line)
    elif in_sec == sec_rodata:
        s_rodata += fix_globals(line)
    else:
        print("ERROR patching assembly")
        sys.exit(1)


for line in s_other:
    print(line)


# Stick the preamble here so we pack everything from this point till
# ifname_payload_start, making sure all user-defined function and variables
# are packed.
preamble = ''
preamble += '    .text\n'
preamble += '    .p2align    3,,7\n'
preamble += '    .global {0}_patch_got\n'   # GOT page base address accessor
preamble += '    .type   {0}_patch_got, %function\n'
preamble += '{0}_patch_got:\n'
preamble += '    adrp    x0, :got:_GLOBAL_OFFSET_TABLE_\n'
preamble += '    adr x1, {0}$got\n'
preamble += '    str x0, [x1]\n'
preamble += '    ret\n'
preamble += '    .p2align    3,,7\n'
preamble += '    .global {0}_preamble\n' # Shipped code starts here
preamble += '    .type   {0}_preamble, %function\n'
preamble += '{0}_preamble:\n'
preamble += '    b   .Lbegin\n'          # Branch to actual beginning of code
preamble += '    .global {0}_got\n'      # GOT base address pointer storage
preamble += '    .type   {0}_got, %object\n'
preamble += '{0}_got:\n'
preamble += '{0}$got:\n'                 # Make the linker happy
preamble += '    .quad   0'
print(preamble.format(ifname))


for line in s_text:
    # Note: these alignment increases ifunc size significantly for small active
    # messages. Can fix later to be more selective.
    #   Find 4B alignment directives: ^\s*\.align\s+2 => \t.align\t6
    if re.match("^\s*\.align\s+", line) is not None:
        # Skip alignment directives
        continue
    elif re.match("^\s*{}_main:$".format(ifname), line) is not None:
        # Find the ifunc main function
        print(line)
        print(".Lbegin:")   # Add a label for jumping from the preamble
    elif re.match("^\s*adrp\s+([^,]+), (?:_GLOBAL_OFFSET_TABLE_|:got:\S+)$", line) is not None:
        # Find a 2-op GOT reference, replace address calc with load from GOT patch
        m = re.match("^\s*adrp\s+([^,]+), (?:_GLOBAL_OFFSET_TABLE_|:got:\S+)$", line)
        print("    ldr {}, {}$got".format(m.group(1), ifname))
        # Don't print the line we are replacing
        # IFUNCTODO: This seems unused?
    elif re.match("^\s*ldr\s+([^,]+), :got:(\S+)$", line) is not None:
        # Find a 1-op GOT reference, replace address calc with load from GOT patch
        m = re.match("^\s*ldr\s+([^,]+), :got:(\S+)$", line)
        print("    ldr {}, {}$got".format(m.group(1), ifname))
        print("    ldr {0}, [{0}, #:got_lo12:{1}]".format(m.group(1), m.group(2)))
    elif re.match("(?:\A|\W+)\.size\s+{},\s*(.*)".format(ifname), line) is not None:
        # Find size marker for main ifunc function and print size symbol
        print(line)
        # IFUNCTODO: this does not mark end of function, currently no good way to detect
    else:
        print(line)


# Assuming main ifunc function comes last in text assembly, insert prolog
for line in s_rodata:
    print(line)


print("    .p2align    3,,7")
# Mark the end of ifunc code & data, just before the payload of a ifunc message
print(".Lpayload_start:")
print("    .global {}_payload_start".format(ifname))
print("{}_payload_start:".format(ifname))


for line in s_data:
    print(line)
