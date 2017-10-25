#!/usr/bin/env python3
import os
import sys
import re
import itertools as itools
import argparse
from collections import defaultdict
import subprocess
import webbrowser
import shutil
import functools
from jinja2 import Environment

import elftools.elf.structs

from elftools.elf.structs import ELFStructs

@functools.lru_cache(maxsize=8) # 4 __should__ be sufficiant, but 8 cannot hurt
class CachingELFStructs(ELFStructs):
    def __init__(self, little_endian=True, elfclass=32):
        super().__init__(little_endian, elfclass)

elftools.elf.structs.ELFStructs = CachingELFStructs



try:
    from termcolor import colored
except ImportError:
    print("termcolor is not installed; output will be lacking colours", file=sys.stderr)
    def colored(*args, **kwargs):
        return args[0]
    
try:
    from tqdm import tqdm
except ImportError:
    print("tqdm is not installed. Progress bars are disabled")
    def tqdm(iterable):
        return iterable

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str


TEMPLATE = """
<html>
  <head>
    <meta charset="UTF-8">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/foundation/6.2.0/foundation-flex.min.css" rel="stylesheet">
    <title>Broken package report</title>
  </head>
  <body>
    <div id="packagelist" class="row">
      <h1>Broken package report</h1>
      <table id="pkgtable" class="hover" border="1">
        <thead>
          <tr>
            <th>Broken package</th>
            <th>Broken file</th>
            <th>Missing .so files</th>
          </tr>
         </thead>
         <tbody>
           {% for broken_package, missing_so_files in broken_packages.items() | sort %}
           {% for missing_so, broken_file in missing_so_files %}
           <tr>
             {% if loop.first %}
             <td rowspan="{{loop.length}}" >{{broken_package}}</td>
             {% endif %}
             <td>{{broken_file}}</td>
             <td>{{missing_so}}</td>
           </tr>
           {% endfor %}
           {% endfor %}
         </tbody>
      </table>
    </div>
  </body>
</html>
"""

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

                    # we try to avoid superfluous work by not calling
                    # elffile.itersections() directly
                    # Instead we use the lower level API and continue
                    # if the section type is not SHT_DYNAMIC
                    # We can thus avoid to construct Section objects
                    for i in range(elffile.num_sections()):
                        section_header = elffile._get_section_header(i)
                        sectype = section_header['sh_type']
                        if sectype != 'SHT_DYNAMIC':
                            continue
                        name = elffile._get_section_name(section_header)
                        section = DynamicSection(section_header, name,
                                                 elffile.stream,
                                                 elffile)

                        for tag in section.iter_tags('DT_NEEDED'):
                            self.lib2required_by[tag.needed].append(sofile)
                        break # there should only be one dyanmic section

                except ELFError:
                    pass  # not an ELF file
        except PermissionError:
            warn("Could not open {}; please check permissions".format(sofile))

    def check(self):
        print("Checking libraries and binaries")
        for lib_or_bin in tqdm(list(itools.chain(self.enumerate_shared_libs(), self.enumerate_binaries()))):
            self.collect_needed(lib_or_bin)
        missing_libs = self.lib2required_by.keys()  - self.found
        broken_package = defaultdict(set)
        print("Determining broken packages")
        for missing_lib in tqdm(missing_libs):
            demanders = self.lib2required_by[missing_lib]
            try:
                out = subprocess.check_output(["pacman", "-Qoq"] + demanders)
            except subprocess.CalledProcessError:
                warn("Could not get owner for %s" % ", ".join(demanders))
                out = b""
            for index, pkg in enumerate(out.strip().decode("utf-8").split()):
                broken_package[pkg].add((missing_lib, demanders[index]))
        return missing_libs, broken_package

    def report(self):
        missing_libs, broken_packages = self.check()
        template = Environment().from_string(TEMPLATE)
        html = template.render(broken_packages=broken_packages)
        return html


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli-only", "-c",
                        action="store_true",
                        help="Do not display report in browser"
                        )
    parser.add_argument("--out", "-o",
                        help="Path were report should be stored. Default: /tmp",
                        default="/tmp"
                        )
    parser.add_argument("--gui-only", "-g",
                        action="store_true",
                        help="only show gui output")
    args = parser.parse_args()
    if args.gui_only and args.cli_only:
        print("Only means that there is only one. Defaulting to cli")
        args.gui_only = False
    cliviewer = shutil.which("elinks")
    cliviewer = cliviewer or shutil.which("html2text")
    if args.cli_only and not cliviewer:
        warn("To show the output in your terminal, please install either elinks or html2text")
        warn("Exiting now")
        sys.exit(1)
    b = BrokenFinder()
    htmlreport = b.report()
    out_name = "out.html"
    out_path = os.path.join(args.out, out_name)
    with open(out_path, "w") as f:
        f.write(htmlreport)
    if cliviewer and not args.gui_only:
        if "elinks" in cliviewer:
            subprocess.check_call([cliviewer, "--dump", out_path])
        else:
            subprocess.check_call([cliviewer, out_path])
    if not args.cli_only:
        webbrowser.open(out_path)
