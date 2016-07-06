"""Helper functions to handle file operations"""
import logging
import os
import shutil
import six
import hashlib
import tempfile
log = logging.getLogger(__name__)


def compare(file1, file2):
    """compares the contents of two files, passed in either as
       open file handles or accessible file paths. Does a simple
       naive string comparison, so do not use on larger files"""
    if isinstance(file1, six.string_types):  # pragma: no branch
        file1 = open(file1, 'r', True)
    if isinstance(file2, six.string_types):  # pragma: no branch
        file2 = open(file2, 'r', True)
    file1_contents = file1.read()
    file2_contents = file2.read()
    return file1_contents == file2_contents


def sha1sum(f):
    """Return the SHA-1 hash of the contents of file `f`, in hex format"""
    h = hashlib.sha1()
    fp = open(f, 'rb')
    while True:
        block = fp.read(512 * 1024)
        if not block:
            break
        h.update(block)
    return h.hexdigest()


def safe_copyfile(src, dest):
    """safely copy src to dest using a temporary intermediate and then renaming
    to dest"""
    fd, tmpname = tempfile.mkstemp(dir=os.path.dirname(dest))
    shutil.copyfileobj(open(src, 'rb'), os.fdopen(fd, 'wb'))
    shutil.copystat(src, tmpname)
    os.rename(tmpname, dest)
