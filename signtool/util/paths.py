import os.path
import sys
import fnmatch
import logging
# TODO: Use util.commands
from subprocess import PIPE, Popen

log = logging.getLogger(__name__)


def cygpath(filename):
    """Convert a cygwin path into a windows style path"""
    if sys.platform == 'cygwin':
        proc = Popen(['cygpath', '-am', filename], stdout=PIPE)
        return proc.communicate()[0].strip()
    else:
        return filename


def convertPath(srcpath, dstdir):
    """Given `srcpath`, return a corresponding path within `dstdir`"""
    bits = srcpath.split("/")
    bits.pop(0)
    # Strip out leading 'unsigned' from paths like unsigned/update/win32/...
    if bits[0] == 'unsigned':
        bits.pop(0)
    return os.path.join(dstdir, *bits)


def findfiles(roots, includes=('*', ), excludes=()):
    retval = []
    if not isinstance(roots, (list, tuple)):
        roots = [roots]
    for fn in roots:
        if os.path.isdir(fn):
            dirname = fn
            for root, dirs, files in os.walk(dirname):
                for f in files:
                    fullpath = os.path.join(root, f)
                    if not any(fnmatch.fnmatch(f, pat) for pat in includes):
                        log.debug("Skipping %s; doesn't match any include pattern", f)
                        continue
                    if any(fnmatch.fnmatch(f, pat) for pat in excludes):
                        log.debug("Skipping %s; matches an exclude pattern", f)
                        continue
                    retval.append(fullpath)
        else:
            retval.append(fn)
    return retval


def finddirs(root):
    """Return a list of all the directories under `root`"""
    retval = []
    for root, dirs, files in os.walk(root):
        for d in dirs:
            retval.append(os.path.join(root, d))
    return retval
