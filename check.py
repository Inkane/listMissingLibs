#!/usr/bin/env python3
import os
import re
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str

class BrokenFinder():

    def __init__(self):
        self.needed = set() # shared libraries which are needed by others or by programs
        self.found = set()  # 'shared libraries' (could also be symlinks) that we found so far

    def enumerate_shared_libs(self):
        somatching = re.compile(r""".*\.so\Z # normal shared object
        |.*\.so(\.\d+)+ # versioned shared object""", re.VERBOSE)
        for dpath, dnames, fnames in os.walk("/usr"):
            for fullname, fname in ((os.path.join(dpath, fname),fname) for fname in fnames if re.match(somatching ,fname)):
                self.found.add(fname)
                if not os.path.islink(fullname):
                    yield fullname

    def list_needed(self, sofile):
        with open(sofile, 'rb') as f:
            try:
                elffile = ELFFile(f)
                for section in elffile.iter_sections():
                    if not isinstance(section, DynamicSection):
                        continue

                    for tag in section.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            yield bytes2str(tag.needed)
                raise StopIteration
            except ELFError:
                raise StopIteration  # not an ELF file


    def check(self):
        for solib in self.enumerate_shared_libs():
            self.needed.update(set(self.list_needed(solib)))
        print(self.needed  - self.found)

b = BrokenFinder()
b.check()
