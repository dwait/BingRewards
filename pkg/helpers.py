#
# developed by Sergey Markelov (2013)
#

from __future__ import with_statement, division

import zlib
import gzip
import os
import errno
import cgi
from datetime import datetime
import sys

import six

class BingAccountError(ValueError):
    def __init__(self, message):
        Exception.__init__(self, message)

RESULTS_DIR = "result/"

def getXmlChildNodes(xmlNode):
    childNodes = None
    version = sys.version_info
    if version[0] == 2 and version[1] < 7:
        childNodes = xmlNode.getchildren()
    else:
        childNodes = list(xmlNode)
    return childNodes

def getLoggingTime():
    dt = datetime.now()
    dtStr = dt.strftime("%Y-%m-%d %H:%M:%S") + "." + str(dt.microsecond // 100000)
    return dtStr

def createResultsDir(f):
    """
    Creates results dir where all output will go based on
    __file__ object which is passed through f

    Note: results dir is created with 755 mode

    RESULTS_DIR global variable will be updated
    """
    global RESULTS_DIR
    scriptDir = os.path.dirname(os.path.realpath(f))
    resultsDir = scriptDir + "/" + RESULTS_DIR
    try:
        os.makedirs(resultsDir, 0o755)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    RESULTS_DIR = resultsDir


def getResponseBody(response):
    """Attempts to decode an HTTP response body to a unicode string.

    First, if necessary, the body will be decompressed according to the value of the Content-Encoding header.

    Then, the data will be decoded according to the charset indicated in the Content-Type header. If Content-Type
    is a text media type (text/*) but does not specify charset, ISO-8859-1 is assumed. Otherwise, no decoding is
    attempted.

    If decoding occured, the result is a unicode string (unicode in py2 or str in py3). Otherwise, the result of
    response.read() (decompressed if required by Content-Encoding) is returned.
    """
    encoding = response.headers.get("Content-Encoding")

    if encoding in ("gzip", "x-gzip", "deflate"):
        compressedBody = response.read()
        if encoding == "deflate":
            body = zlib.decompress(compressedBody)
        else:
            fd = six.BytesIO(compressedBody)
            try:
                with gzip.GzipFile(fileobj=fd) as data:
                    body = data.read()
            finally:
                fd.close()
    else:
        body = response.read()

    ctHeader = response.headers.get("Content-Type")
    if ctHeader is not None:
        ctValue, ctParams = cgi.parse_header(ctHeader)
        if "charset" in ctParams:
            body = body.decode(ctParams["charset"], errors="replace")
        elif "text" in ctValue:
            body = body.decode("ISO-8859-1", errors="replace")

    return body

def dumpErrorPage(page):
    """
    Dumps page into a file. The resulting file is placed into RESULTS_DIR subfolder
    with error_dtStr.html name, where dtStr is current date and time with
    microseconds precision

    returns filename
    """
    if page is None: raise TypeError("page is None")

    dtStr = datetime.now().strftime("%Y%m%d-%H%M%S.%f")
    filename = "error_" + dtStr + ".html"
    with open(RESULTS_DIR + filename, "w") as fd:
        fd.write(page)

    return filename

def errorOnText(page, query_string, err):
    p = page.find(query_string)
    if p != -1:
        raise BingAccountError(err)
