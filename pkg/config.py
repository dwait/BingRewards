#
# developed by Sergey Markelov (2013)
#

"""
Configuration processor
works with files like config.xml

Usage:
    from config import Config
    ...
    config.parse(configFile)
"""

import xml.etree.ElementTree as et
import helpers

class ConfigError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class AccountKey:
    def __init__(self):
        self.accountType  = None
        self.accountLogin = None

    def getRef(self):
        return self.accountType + "_" + self.accountLogin

class BingRewardsReportItem(AccountKey):
    def __init__(self):
        AccountKey.__init__(self)

        self.oldPoints       = 0
        self.newPoints       = 0
        self.pointsEarned    = 0
        self.pointsEarnedRetrying = 0
        self.lifetimeCredits = 0
        self.retries         = 0
        self.notify          = None         # a reference to an instance of Config.Event.Notify which caused this notification
        self.error           = None         # will be populated with exception if it happens

class Config:
    """Data model of config.xml"""

    class General:
        def __init__(self):
            self.betweenQueriesInterval  = 1.0    # default to this number of seconds
            self.betweenQueriesSalt      = 3.0    # default to this number of seconds
            self.betweenAccountsInterval = 30.0   # default to this number of seconds
            self.betweenAccountsSalt     = 35.5   # default to this number of seconds
            self.openTopLinkRange        = 5      # default to this number of top links to open
            self.openLinkChance          = .7     # default to this percentage of times to open links
            self.addSearchesDesktop      = 0      # default to this number of additional Desktop searches
            self.addSearchesDesktopSalt  = 0      # default to this number of additional Desktop searches for salt
            self.addSearchesMobile       = 0      # default to this number of additional Mobile searches
            self.addSearchesMobileSalt   = 0      # default to this number of additional Mobile searches for salt

    class Proxy:
        """
        Web proxy for HTTP requests. Currently only HTTP proxy is supported.
        No authentication is supported.
        """
        def __init__(self):
            self.protocols = None                 # a CSV of protocols, i.e. "http,https"
            self.url = None                       # an ip or url and port information, i.e "113.57.252.106:80"
            self.login = None                     # login and password can be None while url can be set,
            self.password = None                  # meaning that the proxy doesn't require auth

    class Account(AccountKey):
        """Data model representing config.xml account"""

        def __init__(self):
            AccountKey.__init__(self)
            self.password = None
            self.disabled = False

        def __eq__(self, other):
            return self.__dict__ == other.__dict__

        __hash__ = None

    class Event:
        """"Data model representing config.xml event"""

        onError          = "onError"
        onComplete       = "onComplete"
        onScriptComplete = "onScriptComplete"
        onScriptFailure  = "onScriptFailure"

        class Specifier:
            """see _Format Specifiers_"""
            IF           = 0x1
            CMD          = 0x2
            CMD_ON_ERROR = 0x4 | CMD
            ALL = IF | CMD | CMD_ON_ERROR
            #
            # _r_ is an instance of BingRewardsReportItem
            #
            Dictionary = {
              # spc     type          lambda
                "%a": ( CMD,          lambda r: r.getRef()             ),
                "%e": ( CMD_ON_ERROR, lambda r: r.error                ),
                "%i": ( CMD,          lambda r: r.notify.ifStatement   ),
                "%l": ( ALL,          lambda r: r.lifetimeCredits      ),
                "%p": ( ALL,          lambda r: r.pointsEarnedRetrying ),
                "%P": ( ALL,          lambda r: r.newPoints            ),
                "%r": ( ALL,          lambda r: r.retries              ) }

            @staticmethod
            def __validateSpecifier(specifier, specifierType = ALL):
                if specifier is None:
                    raise ValueError("specifier is None")
                if specifier not in Config.Event.Specifier.Dictionary:
                    raise KeyError("_specifier_ is not in Config.Event.Specifier.Dictionary")
                if not Config.Event.Specifier.Dictionary[specifier][0] & specifierType:
                    raise LookupError("specifier [" + specifier + "] is not allowed for a given type [" + specifierType + "]")

            @staticmethod
            def getLambda(specifier, specifierType):
                """
                Returns a corresponding lambda expression for a given _specifier_
                This method also validates if a specifier is allowed for a given _specifierType_
                _specifierType_ is one of Config.Event.Specifier.{ IF | CMD }
                """
                Config.Event.Specifier.__validateSpecifier(specifier, specifierType)
                return Config.Event.Specifier.Dictionary[specifier][1]

            @staticmethod
            def evaluate(specifier, bingRewardsReportItem):
                """
                Evaluates _specifier_ for a given instance of BingRewardsReportItem
                returns the result of the evaluation
                """

                if bingRewardsReportItem is None:
                    raise ValueError("bingRewardsReportItem is None")
                if not isinstance(bingRewardsReportItem, BingRewardsReportItem):
                    raise TypeError("bingRewardsReportItem is not of BingRewardsReportItem type")

                Config.Event.Specifier.__validateSpecifier(specifier)
                func = Config.Event.Specifier.Dictionary[specifier][1]

                return func(bingRewardsReportItem)

        class IfStatement:
            """See config.xml - Section EVENTS.{RETRY|NOTIFY}.IF"""

            #
            # see EVENTS.{RETRY|NOTIFY}.IF::Comparison Operators
            #
            Ops = {
                "eq" : lambda l, r: l == r,
                "ge" : lambda l, r: l >= r,
                "gt" : lambda l, r: l >  r,
                "le" : lambda l, r: l <= r,
                "lt" : lambda l, r: l <  r,
                "ne" : lambda l, r: l != r }

            def __init__(self):
                self.lhs = None           # a reference to a value from Config.Specifier.Dictionary[spc].lambda
                self.op  = None           # a reference to a value from _Ops_ dictionary
                self.rhs = 0              # integer _rhs_ as described in EVENTS.{RETRY|NOTIFY}.IF::Format
                self.string = None        # will hold a string representation (as it is saved in config.xml) of if statement

            def __str__(self):
                return self.string if self.string else "(None)"

            def evaluate(self, bingRewardsReportItem):
                "Evaluates self for a given instance of BingRewardsReportItem"

                if bingRewardsReportItem is None:
                    raise ValueError("bingRewardsReportItem is None")
                if not isinstance(bingRewardsReportItem, BingRewardsReportItem):
                    raise TypeError("bingRewardsReportItem is not of BingRewardsReportItem type")

                return self.op(self.lhs(bingRewardsReportItem), self.rhs)

        class Retry:
            def __init__(self):
                self.ifStatement = None   # Will hold an instance of IfStatement if specified
                self.interval    = 0.0    # (required) - (float) - how many seconds the script should wait between retries
                self.salt        = 0.0    # (optional) - (float) - up to how many seconds to wait on top of interval (rand(0, salt))
                self.count       = 0      # (required) - (unsigned) - how many times to retry

        class Notify:
            def __init__(self):
                self.ifStatement = None   # Will hold an instance of IfStatement if specified
                self.cmd         = None   # an external command to execute on event

        def __init__(self):
            self.type     = None          # one of { onError, onComplete, onScriptComplete, onScriptFailure }
            self.retry    = None          # if config.xml provides, will be EVENTS.RETRY
            self.notifies = list()        # if config.xml provides, will be a list of EVENTS.NOTIFY objects
            self.accounts = dict()        # holds a dictionary of _EventAccount_ objects, where key is AccountKey.getRef()

    class EventAccount(Event):
        def __init__(self):
            Config.Event.__init__(self)
            self.ref = None               # a reference to an account of a format: accountType_accountLogin


    def __init__(self):
        self.general  = Config.General()
        self.proxy    = None              # no proxy by default, otherwise will be an instance of Config.Proxy
        self.accounts = dict()            # holds a dictionary of _Account_ objects
        self.events   = dict()            # holds a dictionary of _Event_ objects

    def __parseAccounts(self, xmlAccountsNode):
        for account in xmlAccountsNode.findall("account"):
            acc = Config.Account()

            acc.disabled = True if account.get("disabled", "false").lower() == "true" else False

            acc.accountType = "Live"

            val = account.find("login")
            if val is None:
                raise ConfigError("accounts.account.login is not found")
            acc.accountLogin = val.text

            val = account.find("password")
            if val is None:
                raise ConfigError("accounts.account.password is not found")
            acc.password = val.text

            val = account.find("ua_desktop")
            if not val is None:
                acc.ua_desktop = val.text

            val = account.find("ua_mobile")
            if not val is None:
                acc.ua_mobile = val.text

            self.accounts[acc.getRef()] = acc

    def __parseEvents(self, xmlEventsNode):
        for event in helpers.getXmlChildNodes(xmlEventsNode):
            ev = Config.Event()
            self.__parseEvent(event, event.tag, ev)
            self.events[ev.type] = ev

    def __parseEvent(self, xmlEventNode, eventType, event):
        try:
            eventMethod = getattr(self, "_" + self.__class__.__name__ + "__parseEvent_" + eventType)
        except AttributeError:
            raise ConfigError("Event type is not supported [" + eventType + "]")

        eventMethod(xmlEventNode, event)

        return event

    # is called from self.__parseEvent
    def __parseEvent_onError(self, xmlEventNode, event):
        return self.__parseOnErrorOnComplete(xmlEventNode, event, "onError")

    # is called from self.__parseEvent
    def __parseEvent_onComplete(self, xmlEventNode, event):
        return self.__parseOnErrorOnComplete(xmlEventNode, event, "onComplete")

    # is called from self.__parseEvent
    def __parseEvent_onScriptComplete(self, xmlEventNode, event):
        return self.__parseEvent_onScriptFailure_onScriptComplete(xmlEventNode, event, Config.Event.onScriptComplete)

    # is called from self.__parseEvent
    def __parseEvent_onScriptFailure(self, xmlEventNode, event):
        return self.__parseEvent_onScriptFailure_onScriptComplete(xmlEventNode, event, Config.Event.onScriptFailure)

    def __parseEvent_onScriptFailure_onScriptComplete(self, xmlEventNode, event, eventType):
        event.type = xmlEventNode.tag
        for node in helpers.getXmlChildNodes(xmlEventNode):
            if node.tag == "notify":
                event.notifies.append(self.__parseEventNotify(node, "cmd"))
            else:
                raise ConfigError("Invalid subnode in EVENTS." + eventType + " - [" + node.tag + "]")

        if not event.notifies:
            raise ConfigError("At least one _notify_ should be in EVENTS." + eventType)

        return event

    def __parseOnErrorOnComplete(self, xmlEventNode, event, eventType):
        event.type = eventType
        for node in helpers.getXmlChildNodes(xmlEventNode):
            if node.tag == "retry":
                event.retry = self.__parseEventRetry(node)
            elif node.tag == "notify":
                event.notifies.append(self.__parseEventNotify(node, ( "cmd", "if" ) ))
            elif node.tag == "account":
                acc = self.__parseEventAccount(node, event, eventType)
                event.accounts[acc.ref] = acc
            else:
                raise ConfigError("Invalid subnode in EVENTS.{onError|onComplete} - [" + node.tag + "]")

        return event

    def __parseEventRetry(self, xmlEventRetryNode):
        retry = Config.Event.Retry()

        val = xmlEventRetryNode.get("if")
        if not val is None:
            retry.ifStatement = self.__parseIfStatement(val)

        val = xmlEventRetryNode.get("interval")
        if val is None:
            raise ConfigError("EVENTS.RETRY.interval is not found")
        try:
            retry.interval = float(val)
        except ValueError:
            raise ConfigError("EVENTS.RETRY.interval must be (double): " + val)
        if retry.interval < 0:
            raise ConfigError("EVENTS.RETRY.interval MUST BE >= 0")

        retry.salt = self.__parseFloatAttr(xmlEventRetryNode, "salt", 0.0, "EVENTS.RETRY.salt")

        val = xmlEventRetryNode.get("count")
        if val is None:
            raise ConfigError("EVENTS.RETRY.count is not found")
        try:
            retry.count = int(val)
        except ValueError:
            raise ConfigError("EVENTS.RETRY.count must be (int): " + val)
        if retry.count <= 0:
            raise ConfigError("EVENTS.RETRY.count MUST BE > 0")

        return retry

    def __parseEventNotify(self, xmlEventNotifyNode, validNodes):
        notify = Config.Event.Notify()

        if "if" in validNodes:
            val = xmlEventNotifyNode.get("if")
            if not val is None:
                notify.ifStatement = self.__parseIfStatement(val)

        if "cmd" in validNodes:
            notify.cmd = xmlEventNotifyNode.get("cmd")
            if notify.cmd is None:
                raise ConfigError("EVENTS.NOTIFY.cmd is not found")

        return notify

    def __parseEventAccount(self, xmlEventAccountNode, event, eventType):
        account = Config.EventAccount()

        account.ref = xmlEventAccountNode.get("ref")
        if account.ref is None:
            raise ConfigError("EVENTS.ACCOUNT.ref is not found")
        elif account.ref not in self.accounts:
            raise ConfigError("Corresponding account is not found for EVENTS.ACCOUNT.ref = [" + account.ref + "]")

        self.__parseEvent(xmlEventAccountNode, eventType, account)

        return account

    def __parseIfStatement(self, strIfStatement):
        """
        Validates _strIfStatement_
        returns an instance of Config.Event.IfStatement
        raises ConfigError
        """

        expression = strIfStatement.split()
        if len(expression) != 3:
            raise ConfigError("EVENTS.{RETRY|NOTIFY}.IF is invalid - expression MUST consist of three parts")

        lhs, op, rhs = expression

        # rhs
        try:
            r = int(rhs)
        except ValueError:
            raise ConfigError("EVENTS.{RETRY|NOTIFY}.IF is invalid - _rhs_ can not be parsed as int")
        if float(r) != float(rhs):
            raise ConfigError("EVENTS.{RETRY|NOTIFY}.IF is invalid - _rhs_ MUST be int")

        # op
        if op not in Config.Event.IfStatement.Ops:
            raise ConfigError("EVENTS.{RETRY|NOTIFY}.IF is invalid - _op_ is not valid")

        ifStatement = Config.Event.IfStatement()
        ifStatement.string = strIfStatement.replace("%", "")
        ifStatement.lhs = Config.Event.Specifier.getLambda(lhs, Config.Event.Specifier.IF)
        ifStatement.op  = Config.Event.IfStatement.Ops[op]
        ifStatement.rhs = r

        return ifStatement

    def __parseFloatAttr(self, xmlNode, attr, default, attrName):
        result = 0
        val = xmlNode.get(attr, default)
        try:
            result = float(val)
        except ValueError:
            raise ConfigError(attrName + " must be (double): " + val)
        if result < 0:
            raise ConfigError(attrName + " MUST BE >= 0")

        return result

    def __parseIntAttr(self, xmlNode, attr, default, attrName):
        result = 0
        val = xmlNode.get(attr, default)
        try:
            result = int(val)
        except ValueError:
            raise ConfigError(attrName + " must be (int): " + val)
        if result < 0:
            raise ConfigError(attrName + " MUST BE >= 0")

        return result

    def __parseGeneral(self, xmlGeneralNode):
        """
        Parses Config.General section
        """
        g = Config.General()

        g.betweenQueriesInterval  = self.__parseFloatAttr(xmlGeneralNode, "betweenQueriesInterval",  g.betweenQueriesInterval,  "general.betweenQueriesInterval")
        g.betweenQueriesSalt      = self.__parseFloatAttr(xmlGeneralNode, "betweenQueriesSalt",      g.betweenQueriesSalt,      "general.betweenQueriesSalt")
        g.betweenAccountsInterval = self.__parseFloatAttr(xmlGeneralNode, "betweenAccountsInterval", g.betweenAccountsInterval, "general.betweenAccountsInterval")
        g.betweenAccountsSalt     = self.__parseFloatAttr(xmlGeneralNode, "betweenAccountsSalt",     g.betweenAccountsSalt,     "general.betweenAccountsSalt")
        g.openTopLinkRange        = self.__parseFloatAttr(xmlGeneralNode, "openTopLinkRange",        g.openTopLinkRange,        "general.openTopLinkRange")
        g.openLinkChance          = self.__parseFloatAttr(xmlGeneralNode, "openLinkChance",          g.betweenAccountsSalt,     "general.openLinkChance")
        g.addSearchesMobile       = self.__parseIntAttr(xmlGeneralNode,   "addSearchesMobile",       g.addSearchesMobile,       "general.addSearchesMobile")
        g.addSearchesMobileSalt   = self.__parseIntAttr(xmlGeneralNode,   "addSearchesMobileSalt",   g.addSearchesMobileSalt,   "general.addSearchesMobileSalt")
        g.addSearchesDesktop      = self.__parseIntAttr(xmlGeneralNode,   "addSearchesDesktop",      g.addSearchesDesktop,      "general.addSearchesDesktop")
        g.addSearchesDesktopSalt  = self.__parseIntAttr(xmlGeneralNode,   "addSearchesDesktopSalt",  g.addSearchesDesktopSalt,  "general.addSearchesDesktopSalt")

        self.general = g

    def __parseQueries(self, xmlQueriesNode):
        """
        Parses self.queryGenerator
        """
        generator = xmlQueriesNode.get("generator")
        if generator is None:
            raise ConfigError("queries.generator is not found")

        self.queryGenerator = generator

    def __parseProxy(self, node):
        """
        Parses Config.Proxy section
        """
        p = Config.Proxy()

        t = node.get("protocols")
        if t is None:
            raise ConfigError("proxy.protocols is not found")
        p.protocols = t.split(',')

        p.url = node.get("url")
        if p.url is None:
            raise ConfigError("proxy.url is not found")

        p.login    = node.get("login")
        p.password = node.get("password")

        if p.login or p.password:
            if not p.login or not p.password:
                raise ConfigError("Both proxy login and proxy password should be either set or unset at the same time")

        self.proxy = p

    def getEvent(self, eventType, accountKey = None):
        """
        Returns an event of type _eventType_ for account _accountKey_ (if it is passed)
        or global event if there is no specific event for _accountKey_
        or None if the event of type _eventType_ is not found
        """
        if eventType is None:
            raise ValueError("eventType is None")
        if accountKey and not isinstance(accountKey, AccountKey):
            raise TypeError("accountKey not of AccountKey type")

        if self.events is None or eventType not in self.events:
            return None

        event = self.events[eventType]

        if accountKey:
            ref = accountKey.getRef()
            if ref in event.accounts:
                event = event.accounts[ref]

        return event

    def __parse(self, root):
        for node in helpers.getXmlChildNodes(root):
            if node.tag == "general":
                self.__parseGeneral(node)
            elif node.tag == "proxy":
                self.__parseProxy(node)
            elif node.tag == "accounts":
                self.__parseAccounts(node)
            elif node.tag == "events":
                self.__parseEvents(node)
            elif node.tag == "queries":
                self.__parseQueries(node)
            else:
                raise ConfigError("Invalid subnode configuration root - [" + node.tag + "]")

    def parseFromFile(self, configFile):
        """
        Parses a configuration file
        configFile - config.xml like file to parse
        raises ConfigError if config.xml is not correct
        raises ValueError if _configFile_ is None
        """
        if configFile is None:
            raise ValueError("_configFile_ is None")

        self.accounts.clear()
        self.events.clear()
        self.queryGenerator = None

        tree = et.parse(configFile)
        root = tree.getroot()
        self.__parse(root)

    def parseFromString(self, xmlString):
        """
        Parses a configuration from _xmlString_
        _xmlString_ - an xml string like config.xml
        raises ConfigError if _xmlString_ is not correct
        raises ValueError if _xmlString_ is None
        """
        if xmlString is None:
            raise ValueError("_xmlString_ is None")

        self.accounts.clear()
        self.events.clear()
        self.queryGenerator = None

        root = et.fromstring(xmlString)
        self.__parse(root)
