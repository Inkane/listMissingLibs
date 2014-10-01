#!/usr/bin/env python3
import os
import re
import itertools as itools
from collections import defaultdict

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str

class BrokenFinder():

    def __init__(self):
        self.found = set()  # 'shared libraries' (could also be symlinks) that we found so far
        self.lib2required_by = defaultdict(list)
        # get all directories in PATH;  if unset, use "/usr/bin" as a default
        self.bindirs = os.environ.get("PATH", "/usr/bin").split(":")

    def enumerate_shared_libs(self):
        somatching = re.compile(r""".*\.so\Z # normal shared object
        |.*\.so(\.\d+)+ # versioned shared object""", re.VERBOSE)
        for dpath, dnames, fnames in os.walk("/usr"):
            for fullname, fname in ((os.path.join(dpath, fname),fname) for fname in fnames if re.match(somatching ,fname)):
                self.found.add(fname)
                if not os.path.islink(fullname):
                    yield fullname

    def enumerate_binaries(self):
        for dpath, dnames, fnames in itools.chain(*(os.walk(bindir) for bindir in self.bindirs)):
            for fname in fnames:
                fullname = os.path.join(dpath, fname)
                if not os.path.islink(fullname):
                    yield fullname

    def collect_needed(self, sofile):
        try:
            with open(sofile, 'rb') as f:
                try:
                    elffile = ELFFile(f)
                    for section in elffile.iter_sections():
                        if not isinstance(section, DynamicSection):
                            continue

                        for tag in section.iter_tags():
                            if tag.entry.d_tag == 'DT_NEEDED':
                                self.lib2required_by[bytes2str(tag.needed)].append(sofile)

                except ELFError:
                    pass  # not an ELF file
        except PermissionError:
            print("Could not open {}; please check permissions".format(sofile))

    def check(self):
        for lib_or_bin in itools.chain(self.enumerate_shared_libs(), self.enumerate_binaries()):
            self.collect_needed(lib_or_bin)
        missing_libs = self.lib2required_by.keys()  - self.found
        if missing_libs:
            print("==The following libraries were not found")
        for missing_lib in (missing_libs):
            print("{} required by: {}".format(missing_lib, ', '.join(self.lib2required_by[missing_lib])))

b = BrokenFinder()
b.check()
