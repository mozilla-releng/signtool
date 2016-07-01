import base64
import hashlib
import os
import requests
import socket
from subprocess import check_call
import time
import urllib

import six.moves.http_client as httplib
from six.moves.urllib.error import HTTPError, URLError
from six.moves.urllib.request import urlopen, Request

from signtool.util.file import sha1sum, copyfile

import logging
log = logging.getLogger(__name__)


def getfile(baseurl, filehash, format_, cert, method):
    url = "%s/sign/%s/%s" % (baseurl, format_, filehash)
    log.debug("%s: GET %s", filehash, url)
    return method(url, verify=cert)


def get_token(baseurl, username, password, slave_ip, duration):
    auth = base64.encodestring('%s:%s' % (username, password)).rstrip('\n')
    url = '%s/token' % baseurl
    data = urllib.urlencode({
        'slave_ip': slave_ip,
        'duration': duration,
    })
    headers = {
        'Authorization': 'Basic %s' % auth,
        'Content-Length': str(len(data)),
    }
    r = Request(url, data, headers)
    return urlopen(r).read()


def check_cached_fn(options, cached_fn, filehash, filename, dest):
    log.debug("%s: checking cache", filehash)
    if os.path.exists(cached_fn):
        log.info("%s: exists in the cache; copying to %s", filehash, dest)
        cached_fp = open(cached_fn, 'rb')
        tmpfile = dest + '.tmp'
        hsh = hashlib.new('sha1')
        with open(tmpfile, 'wb') as fp:
            while True:
                data = cached_fp.read(1024 ** 2)
                if not data:
                    break
                hsh.update(data)
                fp.write(data)
        newhash = hsh.hexdigest()
        if os.path.exists(dest):
            os.unlink(dest)
        os.rename(tmpfile, dest)
        log.info("%s: OK", filehash)
        # See if we should re-sign NSS
        if options.nsscmd and filehash != newhash and os.path.exists(os.path.splitext(filename)[0] + ".chk"):
            cmd = '%s "%s"' % (options.nsscmd, dest)
            log.info("Regenerating .chk file")
            log.debug("Running %s", cmd)
            check_call(cmd, shell=True)
        return True


def remote_signfile(options, urls, filename, fmt, token, dest=None):
    filehash = sha1sum(filename)
    if dest is None:
        dest = filename

    if fmt == 'gpg':
        dest += '.asc'

    parent_dir = os.path.dirname(os.path.abspath(dest))
    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)

    # Check the cache
    cached_fn = None
    if options.cachedir:
        cached_fn = os.path.join(options.cachedir, fmt, filehash)
        result = check_cached_fn(options, cached_fn, filehash, filename, dest)
        if result:
            return True

    errors = 0
    pendings = 0
    max_errors = 5
    # It takes the server ~60s to respond to an attempting to get a signed file
    # We want to give up after about 5 minutes, so 60*5 = 5 tries.
    max_pending_tries = 5
    while True:
        if pendings >= max_pending_tries:
            log.error("%s: giving up after %i tries", filehash, pendings)
            # If we've given up on the current server, try a different one!
            urls.pop(0)
            urls.append(url)
            errors += 1
            # Pendings needs to be reset to give the next server a fair shake.
            pendings = 0
        if errors >= max_errors:
            log.error("%s: giving up after %i tries", filehash, errors)
            return False
        # Try to get a previously signed copy of this file
        try:
            url = urls[0]
            log.info("%s: processing %s on %s", filehash, filename, url)
            r = getfile(url, filehash, fmt, options.cert, requests.get)
            r.raise_for_status()
            responsehash = r.headers['X-SHA1-Digest']
            tmpfile = dest + '.tmp'
            with open(tmpfile, 'wb') as fd:
                for chunk in r.iter_content(1024 ** 2):
                    fd.write(chunk)
            newhash = sha1sum(tmpfile)
            if newhash != responsehash:
                log.warn(
                    "%s: hash mismatch; trying to download again", filehash)
                os.unlink(tmpfile)
                errors += 1
                continue
            if os.path.exists(dest):
                os.unlink(dest)
            os.rename(tmpfile, dest)
            log.info("%s: OK", filehash)
            # See if we should re-sign NSS
            if options.nsscmd and filehash != responsehash and os.path.exists(os.path.splitext(filename)[0] + ".chk"):
                cmd = '%s "%s"' % (options.nsscmd, dest)
                log.info("Regenerating .chk file")
                log.debug("Running %s", cmd)
                check_call(cmd, shell=True)

            # Possibly write to our cache
            if cached_fn:
                cached_dir = os.path.dirname(cached_fn)
                if not os.path.exists(cached_dir):
                    log.debug("Creating %s", cached_dir)
                    os.makedirs(cached_dir)
                log.info("Copying %s to cache %s", dest, cached_fn)
                copyfile(dest, cached_fn)
            break
        except HTTPError as e:
            try:
                if 'X-Pending' in e.headers:
                    log.debug("%s: pending; try again in a bit", filehash)
                    time.sleep(15)
                    pendings += 1
                    continue
            except:
                raise

            errors += 1

            # That didn't work...so let's upload it
            log.info("%s: uploading for signing", filehash)
            req = None
            try:
                try:
                    nonce = open(options.noncefile, 'rb').read()
                except IOError:
                    nonce = ""
                req = uploadfile(url, filename, fmt, token, nonce=nonce)
                nonce = req.info()['X-Nonce']
                open(options.noncefile, 'wb').write(nonce)
            except HTTPError as e:
                # python2.5 doesn't think 202 is ok...but really it is!
                if 'X-Nonce' in e.headers:
                    log.debug("updating nonce")
                    nonce = e.headers['X-Nonce']
                    open(options.noncefile, 'wb').write(nonce)
                if e.code != 202:
                    log.exception("%s: error uploading file for signing: %s %s",
                                  filehash, e.code, e.msg)
                    urls.pop(0)
                    urls.append(url)
            except (URLError, socket.error, httplib.BadStatusLine):
                # Try again in a little while
                log.exception("%s: connection error; trying again soon", filehash)
                # Move the current url to the back
                urls.pop(0)
                urls.append(url)
            time.sleep(1)
            continue
        except (URLError, socket.error):
            # Try again in a little while
            log.exception("%s: connection error; trying again soon", filehash)
            # Move the current url to the back
            urls.pop(0)
            urls.append(url)
            time.sleep(1)
            errors += 1
            continue
    return True


def uploadfile(baseurl, filename, format_, token, nonce):
    """Uploads file (given by `filename`) to server at `baseurl`.

    `sesson_key` and `nonce` are string values that get passed as POST
    parameters.
    """
    filehash = sha1sum(filename)

    # from http://stackoverflow.com/questions/10546437/problems-using-multipart-encode-poster-library
    items = []
    params = {
        'sha1': filehash,
        'filename': os.path.basename(filename),
        'token': token,
        'nonce': nonce,
    }
    # items.append(MultipartParam.from_file('filedata', filename))

    #datagen, headers = multipart_encode(items)
    #r = Request(
    #    "%s/sign/%s" % (baseurl, format_), datagen, headers)
    #return urlopen(r)
