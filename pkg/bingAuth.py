#
# developed by Sergey Markelov (2013)
#

import random
import re
import time
import json

from six.moves import urllib

import bingCommon
import helpers

class AuthenticationError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class BingAuth:
    inputNameValue = re.compile(r"<input.+?name=\"(.+?)\".+?value=\"(.+?)\"")
    formAction = re.compile(r"<form.+action=\"(.+?)\"")
    ppftValue = re.compile(r"sFTTag:'.+value=\"(.+?)\"")
    ppsxValue = re.compile(r":'(Pa?s?s?p?o?r?t?R?N?)'")
    winLiveId = re.compile(r"\"WindowsLiveId\":\"(.+?)\"")
    urlPostValue = re.compile(r"urlPost:'(.+?)'")

    def __init__(self, httpHeaders, opener):
        """
        @param opener is an instance of urllib.request.OpenerDirector
        """
        if opener is None or not isinstance(opener, urllib.request.OpenerDirector):
            raise TypeError("opener is not an instance of urllib.request.OpenerDirector")

        self.opener = opener
        self.httpHeaders = httpHeaders

    def authenticate(self, authType, login, password):
        """
        throws ValueError if login or password is None
        throws AuthenticationError
        """
        if login is None: raise ValueError("login is None")
        if password is None: raise ValueError("password is None")

        """
        Authenticates a user on bing.com with his/her Live account.

        throws AuthenticationError if authentication can not be passed
        throws urllib2.HTTPError if the server couldn't fulfill the request
        throws urllib2.URLError if failed to reach the server
        """
        # request http://www.bing.com
        request = urllib.request.Request(url = bingCommon.BING_URL, headers = self.httpHeaders)
        with self.opener.open(request) as response:
            page = helpers.getResponseBody(response)

        # get connection URL for provider Live
        urlSearch = self.winLiveId.search(page)
        if urlSearch is None:
            raise AuthenticationError("Could not find variable 'WindowsLiveId' on Live login page")
        url = urlSearch.group(1).encode("ascii").decode("unicode_escape")

        request = urllib.request.Request(url = url, headers = self.httpHeaders)
        request.add_header("Referer", bingCommon.BING_URL)
        with self.opener.open(request) as response:
            referer = response.geturl()
            page = helpers.getResponseBody(response)

        # get PPFT parameter
        PPFTSearch = self.ppftValue.search(page)
        if PPFTSearch is None:
            raise AuthenticationError("Could not find variable 'PPFT' on Live login page")
        PPFT = PPFTSearch.group(1).encode("ascii")

        # get PPSX parameter
        ppsxSearch = self.ppsxValue.search(page)
        if ppsxSearch is None:
            raise AuthenticationError("Could not find PassportRN variable on Live login page")
        PPSX = ppsxSearch.group(1).encode("ascii")

        # generate ClientLoginTime
        clt = 20000 + int(random.uniform(0, 1000))
        bclt = str(clt).encode("ascii")

        # get url to post data to
        urlSearch = self.urlPostValue.search(page)
        if urlSearch is None:
            raise AuthenticationError("Could not find variable 'urlPost' on Live login page")
        url = urlSearch.group(1)

        timestamp = int(time.time() * 1000)
        # TODO: randomize times a bit?
        i16 = json.dumps({
            "navigationStart": timestamp,
            "unloadEventStart": timestamp + 209,
            "unloadEventEnd": timestamp + 210,
            "redirectStart": 0,
            "redirectEnd": 0,
            "fetchStart": timestamp + 73,
            "domainLookupStart": timestamp + 73,
            "domainLookupEnd": timestamp + 130,
            "connectStart": timestamp + 130,
            "connectEnd": timestamp + 130,
            "secureConnectionStart": timestamp + 210,
            "requestStart": timestamp + 183,
            "responseStart": timestamp + 205,
            "responseEnd": timestamp + 205,
            "domLoading": timestamp + 208,
            "domInteractive": timestamp + 406,
            "domContentLoadedEventStart": timestamp + 420,
            "domContentLoadedEventEnd": timestamp + 420,
            "domComplete": timestamp + 422,
            "loadEventStart": timestamp + 422,
            "loadEventEnd": 0
        }, ensure_ascii=True).encode("ascii")

        blogin = login.encode("utf-8")
        bpassword = password.encode("utf-8")

        postFields = urllib.parse.urlencode({
            b"loginfmt"      : blogin,
            b"login"         : blogin,
            b"passwd"        : bpassword,
            b"type"          : b"11",
            b"PPFT"          : PPFT,
            b"PPSX"          : PPSX,
            b"LoginOptions"  : b"3",
            b"FoundMSAs"     : b"",
            b"fspost"        : b"0",
            b"NewUser"       : b"1",
            b"i2"            : b"1", # ClientMode
            b"i13"           : b"0", # ClientUsedKMSI
            b"i16"           : i16,
            b"i19"           : bclt, # ClientLoginTime
            b"i21"           : b"0",
            b"i22"           : b"0",
            b"i17"           : b"0", # SRSFailed
            b"i18"           : b"__DefaultLogin_Strings|1,__DefaultLogin_Core|1," # SRSSuccess
        }).encode("ascii")

        # get Passport page
        request = urllib.request.Request(url, postFields, self.httpHeaders)
        request.add_header("Referer", referer)
        with self.opener.open(request) as response:
            referer = response.geturl()
            page = helpers.getResponseBody(response)

        # Checking for bad usernames and password
        helpers.errorOnText(page, "That password is incorrect.", "Authentication has not been passed: Invalid password")
        helpers.errorOnText(page, "That Microsoft account doesn't exist", "Authentication has not been passed: Invalid username")
        # check if there is a new terms of use
        helpers.errorOnText(page, "//account.live.com/tou/accrue", "Please log in (log out first if necessary) through a browser and accept the Terms Of Use")

        contSubmitUrl = self.formAction.search(page)
        if contSubmitUrl is None:
            raise AuthenticationError("Could not find form action for continue page")
        url = contSubmitUrl.group(1)

        # get all form inputs
        formFields = self.inputNameValue.findall(page)
        postFields = {}
        for field in formFields:
            postFields[field[0].encode("ascii")] = field[1].encode("ascii")
        postFields = urllib.parse.urlencode(postFields).encode("ascii")

        # submit continue page
        request = urllib.request.Request(url, postFields, self.httpHeaders)
        request.add_header("Referer", referer)
        with self.opener.open(request) as response:
            referer = response.geturl()
            page = helpers.getResponseBody(response)

        request = urllib.request.Request(url = bingCommon.BING_URL, headers = self.httpHeaders)
        request.add_header("Referer", referer)
        with self.opener.open(request) as response:
            referer = response.geturl()

            # if that's not bingCommon.BING_URL => authentication wasn't pass => write the page to the file and report
            if referer.find(bingCommon.BING_URL) == -1:
                try:
                    filename = helpers.dumpErrorPage(helpers.getResponseBody(response))
                    s = "check {} file for more information".format(filename)
                except IOError:
                    s = "no further information could be provided - failed to write a file into {} subfolder".format(helpers.RESULTS_DIR)
                raise AuthenticationError("Authentication has not been passed:\n{}".format(s))
