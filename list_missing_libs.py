#!/usr/bin/env python3
import os
import sys
import re
import itertools as itools
from collections import defaultdict
import subprocess

from jinja2 import Environment

try:
    from termcolor import colored
except ImportError:
    print("termcolor is not installed; output will be lacking colours", file=sys.stderr)
    def colored(*args, **kwargs):
        return args[0]

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str

# utilities
def warn(text):
    warning = colored("Warning: >>", 'red')
    text = colored(text, 'white')
    print(warning, text, file=sys.stderr)

def highlight(text):
    return colored(text, 'white', attrs=['bold', 'dark'])


def walk_multi_dir(dirs):
    yield from itools.chain(*(os.walk(d) for d in dirs))

class BrokenFinder():

    def __init__(self):
        self.found = set()  # 'shared libraries' (could also be symlinks) that we found so far
        self.lib2required_by = defaultdict(list)
        # get all directories in PATH;  if unset, use "/usr/bin" as a default
        self.bindirs = os.environ.get("PATH", "/usr/bin").split(":")
        self.libdirs = ["/usr"]
        if os.path.exists("/opt"):
            self.libdirs.append("/opt")

    def enumerate_shared_libs(self):
        somatching = re.compile(r""".*\.so\Z # normal shared object
        |.*\.so(\.\d+)+ # versioned shared object""", re.VERBOSE)
        for dpath, dnames, fnames in walk_multi_dir(self.libdirs):
            for fullname, fname in ((os.path.join(dpath, fname),fname) for fname in fnames if re.match(somatching ,fname)):
                self.found.add(fname)
                if not os.path.islink(fullname):
                    yield fullname

    def enumerate_binaries(self):
        for dpath, dnames, fnames in walk_multi_dir(self.bindirs):
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
            warn("Could not open {}; please check permissions".format(sofile))

    def check(self):
        for lib_or_bin in itools.chain(self.enumerate_shared_libs(), self.enumerate_binaries()):
            self.collect_needed(lib_or_bin)
        missing_libs = self.lib2required_by.keys()  - self.found
        broken_package = defaultdict(set)
        for missing_lib in missing_libs:
            demanders = self.lib2required_by[missing_lib]
            out = subprocess.check_output(["pacman", "-Qoq"] + demanders)
            for index, pkg in enumerate(out.strip().decode("utf-8").split()):
                broken_package[pkg].add((missing_lib, demanders[index]))
        return missing_libs, broken_package

    def report(self):
        missing_libs, broken_packages = self.check()
        with open("./template.html") as f:
            template = Environment().from_string(f.read())
        html = template.render(broken_packages=broken_packages)
        with open("./out.html", "w") as f:
            f.write(html)


if __name__ == "__main__":
    b = BrokenFinder()
    b.report()
