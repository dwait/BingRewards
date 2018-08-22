#
# developed by Sergey Markelov (2013)
#

import random

BING_URL = 'http://www.bing.com'
# When links are hit from dashboard, need to use the account URL, not bing URL.
# Not overwriting because it could be used in other places.
ACCOUNT_URL = 'https://account.microsoft.com'

# common headers for all requests
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-us,en;q=0.5",
    "Accept-Charset": "utf-8",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

class UserAgents:
    @staticmethod
    def generate(account):
        userAgents = UserAgents

        if hasattr(account, "ua_desktop"):
            userAgents.pc = account.ua_desktop
        else:
            userAgents.pc = random.choice(USER_AGENTS_PC)

        if hasattr(account, "ua_mobile"):
            userAgents.mobile = account.ua_mobile
        else:
            userAgents.mobile = random.choice(USER_AGENTS_MOBILE)

        return userAgents

USER_AGENTS_PC = (
    # Safari Mac OSX
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/601.6.17 (KHTML, like Gecko) Version/9.1.1 Safari/601.6.17",
    # Firefox Mac OSX
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:47.0) Gecko/20100101 Firefox/47.0",
    # Firefox Win7
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0",
    # Firefox Win8.1
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0",
    # Firefox Win10
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0",
    # Chrome Mac OSX
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
    # Chrome Win7
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36",
    # Chrome Win8.1
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36",
    # Chrome Win10
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36"
)

USER_AGENTS_MOBILE = (
    # Chrome Android 6.0.1 (LG G5)
    "Mozilla/5.0 (Linux; Android 6.0.1; LGLS992 Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.81 Mobile Safari/537.36",
    # Chrome Android 6.0.1 (Samsung S6 Edge)
    "Mozilla/5.0 (Linux; Android 6.0.1; SM-G925V Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.89 Mobile Safari/537.36",
    # Chrome Android 6.0 (Motorola Droid Turbo 2)
    "Mozilla/5.0 (Linux; Android 6.0; XT1585 Build/MCK24.78-13.12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.81 Mobile Safari/537.36",
    # Chrome Android 5.0 (Galaxy S5)
    "Mozilla/5.0 (Linux; Android 6.0.1; SM-G900V Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.81 Mobile Safari/537.36",
    # Chrome Android 5.1 (Moto X Gen1)
    "Mozilla/5.0 (Linux; Android 5.1; XT1060 Build/LPAS23.12-39.7-1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.81 Mobile Safari/537.36",
    # Chrome iOS 9 (iPhone 6SE)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/51.0.2704.104 Mobile/13F69 Safari/601.1.46",
    # Safari iOS 9 (iPhone 6SE)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13F69 Safari/601.1"
)
