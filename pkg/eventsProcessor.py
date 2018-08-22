#
# developed by Sergey Markelov (2013)
#

import random
import subprocess

from config import Config, BingRewardsReportItem

class EventsProcessor:
    """
    Processes events declared in config.xml
    """
    OK    = 0
    RETRY = 1

    def __init__(self, config, reportItem):
        if config is None: raise ValueError("config is None")
        if not isinstance(config, Config): raise TypeError("config is not of Config type")
        if reportItem is None: raise ValueError("reportItem is None")
        if not isinstance(reportItem, BingRewardsReportItem): raise TypeError("reportItem is not of BingRewardsReportItem type")

        self.config = config
        self.reportItem = reportItem

    def __processRetry(self, retry):
        """
        Returns number of seconds to sleep before the next retry,
        or negative value, indicating no retry should be done
        """
        if self.reportItem.retries >= retry.count:
            return -1
        if retry.ifStatement and not retry.ifStatement.evaluate(self.reportItem):
            return -1

        t = retry.interval + random.uniform(0, retry.salt)
        return t

    def __processNotify(self, notify):
        if notify.ifStatement and not notify.ifStatement.evaluate(self.reportItem):
            return
        self.reportItem.notify = notify
        self.__processCmd(notify.cmd)

    def __processCmd(self, cmd):
        command = cmd
        for specifier in Config.Event.Specifier.Dictionary.keys():
            val = Config.Event.Specifier.evaluate(specifier, self.reportItem)
            command = command.replace(specifier, '"' + str(val) + '"')

        # TODO: check return code from subprocess.call() ?
        subprocess.call(command, shell = True)

    def __processEventOnReportItem(self, eventType):
        event = self.config.getEvent(eventType, self.reportItem)

        if event:
            if event.retry:
                result = self.__processRetry(event.retry)
                if result >= 0:
                    return ( EventsProcessor.RETRY, result )

            if event.notifies:
                for notify in event.notifies:
                    self.__processNotify(notify)

        return (EventsProcessor.OK, 0)

    def processReportItem(self):
        """
        Processes events from self.config based on the result in self.reportItem

        returns a tuple of (resultCode, extra):
        (OK, 0)      - nothing needs to be done, _extra_ can be ignored
        (RETRY, sec) - an account should be retried in _sec_ seconds
        """
        if not self.config.events:
            return (EventsProcessor.OK, 0)

        if self.reportItem.error:
            return self.__processEventOnReportItem(Config.Event.onError)

        return self.__processEventOnReportItem(Config.Event.onComplete)

    @staticmethod
    def onScriptComplete(config):
        """
        Processes Config.Event.onScriptComplete
        _config_ an instance of Config
        returns nothing
        """
        if config is None: raise ValueError("config is None")
        if not isinstance(config, Config): raise TypeError("config is not of Config type")

        event = config.getEvent(Config.Event.onScriptComplete)
        if event is None:
            return

        for notify in event.notifies:
            # TODO: check return code from subprocess.call() ?
            subprocess.call(notify.cmd, shell = True)

    @staticmethod
    def onScriptFailure(config, exception):
        """
        Processes Config.Event.onScriptComplete

        _config_    an instance of Config
        _exception_ is an exception derived from BaseException which caused the script to fail

        By the nature of this function, it won't fail if _exception_ is None or
        is not of the class BaseException, but it's better to supply one.
        This function won't fail if _config_ is not supplied. In that case it will simply return.

        returns nothing
        """
        if config is None: return
        if not isinstance(config, Config): return

        event = config.getEvent(Config.Event.onScriptFailure)
        if event is None:
            return

        description = str(exception) if exception else "No exception was supplied"
        description = "\"" + description.replace("\"", "") + "\""

        for notify in event.notifies:
            cmd = notify.cmd + " " + description
            subprocess.call(cmd, shell = True)
