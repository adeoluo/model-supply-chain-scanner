"""Regenerate crates/msscan-core/src/pickle/stdlib.rs.

Run once per supported CPython version and pass the outputs:
    for v in 3.10 3.11 3.12 3.13 3.14 3.15; do
        uv run --no-project --python $v python -c \
            "import sys; print('\\n'.join(sorted(sys.stdlib_module_names)))" > /tmp/std_$v.txt
    done
    python scripts/gen_stdlib_modules.py /tmp/std_*.txt
"""

from __future__ import annotations

import re
import subprocess
import sys
import textwrap
from pathlib import Path

# Python 2 names, modules removed before 3.10, and the test packages that ship with CPython but
# are left out of sys.stdlib_module_names; a pickle can still reference all of them.
LEGACY = [
    "__builtin__",
    "__builtins__",
    "_builtins",
    "copy_reg",
    "commands",
    "popen2",
    "os2emxpath",
    "cPickle",
    "cStringIO",
    "StringIO",
    "Queue",
    "SocketServer",
    "urllib2",
    "urlparse",
    "httplib",
    "thread",
    "exceptions",
    "new",
    "sets",
    "UserDict",
    "UserList",
    "UserString",
    "ConfigParser",
    "dircache",
    "compiler",
    "rexec",
    "Bastion",
    "ihooks",
    "user",
    "anydbm",
    "whichdb",
    "dbhash",
    "dumbdbm",
    "gdbm",
    "md5",
    "sha",
    "posixfile",
    "mimetools",
    "MimeWriter",
    "rfc822",
    "htmllib",
    "sgmllib",
    "xmllib",
    "fpformat",
    "mhlib",
    "multifile",
    "mutex",
    "toaiff",
    "audiodev",
    "Tkinter",
    "timing",
    "formatter",
    "parser",
    "symbol",
    "macpath",
    "_dummy_thread",
    "dummy_threading",
    "dummy_thread",
    "BaseHTTPServer",
    "SimpleHTTPServer",
    "CGIHTTPServer",
    "Cookie",
    "cookielib",
    "xmlrpclib",
    "SimpleXMLRPCServer",
    "DocXMLRPCServer",
    "robotparser",
    "repr",
    "HTMLParser",
    "htmlentitydefs",
    "markupbase",
    "test",
    "_testcapi",
    "_testinternalcapi",
    "_testbuffer",
    "_testimportmultiple",
    "_testmultiphase",
    "_xxtestfuzz",
    "xxsubtype",
]

TARGET = Path(__file__).resolve().parent.parent / "crates/msscan-core/src/pickle/stdlib.rs"


def main() -> None:
    names = set(LEGACY)
    for arg in sys.argv[1:]:
        names |= set(Path(arg).read_text().split())
    names.discard("__main__")
    body = textwrap.fill(
        ", ".join(f'"{n}"' for n in sorted(names)),
        width=108,
        initial_indent="    ",
        subsequent_indent="    ",
    )
    source = TARGET.read_text()
    updated = re.sub(
        r"(pub const STDLIB_MODULES: &\[&str\] = &\[\n).*?(\n\];)",
        lambda m: f"{m.group(1)}{body},{m.group(2)}",
        source,
        count=1,
        flags=re.S,
    )
    TARGET.write_text(updated)
    # rustfmt lays the list out its own way; leave the file as CI expects it.
    subprocess.run(["cargo", "fmt", "--all"], cwd=TARGET.parents[4], check=True)
    print(f"{len(names)} modules")


if __name__ == "__main__":
    main()
