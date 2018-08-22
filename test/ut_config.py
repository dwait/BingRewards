#!/usr/bin/env python

#
# developed by Sergey Markelov (2013)
#

import os
import unittest
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "pkg"))

from config import AccountKey, Config, ConfigError

class UTConfig(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.configXMLString = """
<configuration>
    <general
        betweenQueriesInterval="12.271"
        betweenQueriesSalt="5.7"
        betweenAccountsInterval="404.1"
        betweenAccountsSalt="40.52" />

    <accounts>
        <account type="Live" disabled="false">
            <login>john.smith@gmail.com</login>
            <password>xxx</password>
        </account>
        <account type="Live" disabled="true">
            <login>google@shmoogle.com</login>
            <password>yyy</password>
        </account>
        <account type="Live" disabled="false">
            <login>ms@ps.com</login>
            <password>zzz</password>
        </account>
        <account type="Live" disabled="false">
            <login>anonymous@anon.com</login>
            <password>aaa</password>
        </account>
        <account type="Live" disabled="false">
            <login>yahoo@oohay.com</login>
            <password>bbb</password>
        </account>
    </accounts>

    <events>
        <onError>
            <retry interval="5" salt="3.5" count="3" />
            <notify cmd="./log.sh error %a %p %r %l %i" />
        </onError>
        <onComplete>
            <retry if="%p lt 16" interval="5" salt="3.5" count="3" />
            <notify if="%l gt 3000" cmd="./log.sh complete %a %p %r %P %l %i" />
            <notify if="%p ne 16" cmd="./log.sh complete %a %p %r %P %l %i" />
            <notify if="%P gt 475" cmd="./log.sh complete %a %p %r %P %l %i" />

            <account ref="Live_john.smith@gmail.com">
                <retry if="%p lt 31" interval="5" salt="3.5" count="3" />
                <notify if="%l gt 10000" cmd="./log.sh complete %a %p %r %P %l %i" />
                <notify if="%p ne 31" cmd="./log.sh complete %a %p %r %P %l %i" />
                <notify if="%P gt 475" cmd="./log.sh complete %a %p %r %P %l %i" />
            </account>

        </onComplete>
        <onScriptComplete>
            <notify cmd="./mail.sh" />
        </onScriptComplete>
        <onScriptFailure>
            <notify cmd="./onScriptFailure.sh" />
        </onScriptFailure>
    </events>
</configuration>
        """
        self.config.parseFromString(self.configXMLString)

    def __checkAccounts(self):
        self.assertIsNotNone(self.config.accounts)
        self.assertEqual(len(self.config.accounts), 5)

        accounts = dict()

        acc = Config.Account()
        acc.accountLogin = "john.smith@gmail.com"
        acc.password = "xxx"
        acc.accountType = "Live"
        acc.disabled = False
        accounts[acc.getRef()] = acc

        acc = Config.Account()
        acc.accountLogin = "google@shmoogle.com"
        acc.password = "yyy"
        acc.accountType = "Live"
        acc.disabled = True
        accounts[acc.getRef()] = acc

        acc = Config.Account()
        acc.accountLogin = "ms@ps.com"
        acc.password = "zzz"
        acc.accountType = "Live"
        acc.disabled = False
        accounts[acc.getRef()] = acc

        acc = Config.Account()
        acc.accountLogin = "anonymous@anon.com"
        acc.password = "aaa"
        acc.accountType = "Live"
        acc.disabled = False
        accounts[acc.getRef()] = acc

        acc = Config.Account()
        acc.accountLogin = "yahoo@oohay.com"
        acc.password = "bbb"
        acc.accountType = "Live"
        acc.disabled = False
        accounts[acc.getRef()] = acc

        self.assertEqual(accounts, self.config.accounts)

    def __checkEvents(self):
        self.assertIsNotNone(self.config.events)
        self.assertEqual(len(self.config.events), 4)
        self.assertTrue(Config.Event.onScriptFailure in self.config.events)
        self.assertTrue(Config.Event.onScriptComplete in self.config.events)
        self.assertTrue(Config.Event.onError in self.config.events)
        self.assertTrue(Config.Event.onComplete in self.config.events)

    def __checkGeneral(self):
        self.assertEqual(self.config.general.betweenQueriesInterval, 12.271)
        self.assertEqual(self.config.general.betweenQueriesSalt, 5.7)
        self.assertEqual(self.config.general.betweenAccountsInterval, 404.1)
        self.assertEqual(self.config.general.betweenAccountsSalt, 40.52)

    def test_event_parse_populatesConfigCorrectly(self):
        self.__checkGeneral()
        self.__checkAccounts()
        self.__checkEvents()

    def test_event_getEvent_returnsEvent(self):
        event = self.config.getEvent(Config.Event.onScriptFailure)
        self.assertIsNotNone(event)
        self.assertTrue(len(event.notifies) == 1)
        self.assertEqual(event.notifies[0].cmd, "./onScriptFailure.sh")

    def test_event_getEvent_returnsOverriddenEventIfExists(self):
        acc = AccountKey()
        acc.accountLogin = "john.smith@gmail.com"
        acc.accountType = "Live"

        event = self.config.getEvent(Config.Event.onComplete, acc)
        self.assertIsNotNone(event)

        self.assertIsNotNone(event.retry.ifStatement)
        self.assertEqual(event.retry.ifStatement.rhs, 31)
        self.assertEqual(event.retry.interval, 5)
        self.assertEqual(event.retry.salt, 3.5)
        self.assertEqual(event.retry.count, 3)

        self.assertEqual(len(event.notifies), 3)
        notify = event.notifies[2]
        self.assertIsNotNone(notify.ifStatement)
        self.assertEqual(notify.ifStatement.rhs, 475)
        self.assertEqual(notify.cmd, "./log.sh complete %a %p %r %P %l %i")

        self.assertEqual(str(notify.ifStatement), "P gt 475")

    def test_event_getEvent_returnsNoneIfEventDoesntExist(self):
        self.assertIsNone(self.config.getEvent("does_not_exist"))

    def test_parseFromString_failsParsingMalformedGeneral(self):
        self.config = Config()
        self.configXMLString = """
<configuration>
    <general betweenQueriesInterval="this_should_be_a_double_number" betweenQueriesSalt="5.7" />
</configuration>
"""
        with self.assertRaises(ConfigError):
            self.config.parseFromString(self.configXMLString)

if __name__ == "__main__":
    unittest.main()
