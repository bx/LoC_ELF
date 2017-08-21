#!/usr/bin/env python2
# MIT License

# Copyright (c) 2017 Rebecca ".bx" Shapiro

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import os
import argparse
from elftools.elf import elffile, constants, enums
import intervaltree
import subprocess


def int_repr(self):
    return "({0:08X}, {1:08X})".format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr


def executable_ranges(path):
    addrs = intervaltree.IntervalTree()
    with open(path, 'rb') as elf:
        ef = elffile.ELFFile(elf)
        for s in ef.iter_sections():
            if (s['sh_flags'] & constants.P_FLAGS.PF_X == constants.P_FLAGS.PF_X) \
               and (not s['sh_type'] == 'SHT_NOBITS') or (u'.text' in s.name):
                va = s['sh_addr']
                end = va + s['sh_size']
                if not (va == end):
                    addrs.add(intervaltree.Interval(va, end))
    addrs.merge_overlaps()
    addrs.merge_equals()
    return addrs


def calculate(path, addr2line):
    intervals = executable_ranges(path)
    paths = set()
    for i in intervals:
        #  print "searching interval (0x%x-0x%x)" % (i.begin, i.end)
        for loc in range(i.begin, i.end):
            cmd = "%s -e %s 0x%x" % (addr2line, path, loc)
            out = subprocess.check_output(cmd, shell=True).strip()
            if not (("??:" in out) or (":?" in out)):
                paths.add(out)
    print "Executable sections are compiled from %d lines of code" % (len(paths))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate # LoC that "
                                     "constitute executable portions of ELF")
    parser.add_argument("-a", "--addr2line", help="path to addr2line",
                        action="store", default="addr2line")
    parser.add_argument("ELF", action="store")
    args = parser.parse_args()
    elf = args.ELF
    addr2line = args.addr2line
    calculate(elf, addr2line)
