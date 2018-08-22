#!/usr/bin/env python2

#
# Bing queries generator
# developed by Sergey Markelov (2013)
#

import re
import helpers
import urllib2
import bingFlyoutParser as bfp
from bingRewards import BingRewards

BING_NEWS_URL = "http://www.bing.com/news?q=world+news"
MAX_QUERY_LEN = 50

class queryGenerator:
    def __init__(self, br):
        """
        param br is a pointer to the calling class bingRewards (used for variables)
        """
        if br is None or not isinstance(br, BingRewards):
            raise ValueError("br is not set or is not an instance of BingRewards")
        self.bingRewards = br
        self.queries = set()

    def __addQueriesFromString(self, inputString):
        """
        Adds all possible query combinations which can be constructed from
        inputString to self.queries

        Returns False if len(self.queries) >= self.numberOfQueries
        meaning no more adding is necessary
        """
        e = len(inputString)
        while(e > 1):
            query = inputString[:e]
            if query not in self.history:
                self.queries.add(query)

            if len(self.queries) >= self.numberOfQueries:
                return False
            e -= 1
            # rstrip()
            while(inputString[e-1:e] in " \u200b"): e -= 1

        return True

    def __splitAndAdd(self, inputString, maxQueryLen):
        """
        Splits inputString into smaller parts each of around maxQueryLen in length
        and calls __addQueriesFromString on each of the smaller parts

        Returns False if len(self.queries) >= self.numberOfQueries
        meaning no more adding is necessary
        """
        s = 0
        resLen = len(inputString)
        e = resLen
        while True:
            while e - s > maxQueryLen:
                t = inputString.rfind(" ", s, e)
                if t == -1: break
                e = t

            if not self.__addQueriesFromString(inputString[s:e]):
                return False

            s = e + 1
            if s >= resLen:
                break
            e = resLen

        return True

    def __generateQueries(self, newsResultSet, maxQueryLen):
        """
        Generates up to self.numberOfQueries queries from newsResultSet

        Returns True if self.numberOfQueries queries were generated in
        self.queries set
        """
        if self.rewardType == bfp.Reward.Type.SEARCH_MOBILE:
            snippetMarkerBegin = '<p class="dgrey"'
            snippetMarkerEnd = '</p>'
        else:
            snippetMarkerBegin = '<span class="sn_snip"'
            snippetMarkerEnd = '</span>'

        snippetMarkerBeginLen = len(snippetMarkerBegin)
        snippetMarkerEndLen = len(snippetMarkerEnd)

        htmlEntities = re.compile("&\w+;")
        trashChars = re.compile("[^\w\d ]")

        s = 0
        while True:
            s = newsResultSet.find(snippetMarkerBegin, s)
            if s == -1: break
            s += snippetMarkerBeginLen
            s = newsResultSet.index(">", s)
            s += 1
            e = newsResultSet.index(snippetMarkerEnd, s)

            # don't include the last "..." character
            e -= 1

            # get rid of unrelated stuff
            inputString, numberOfSubsMade = htmlEntities.subn("", newsResultSet[s:e])
            inputString, numberOfSubsMade = trashChars.subn("", inputString)
            inputString = inputString.strip().replace("  ", " ")

            if not self.__splitAndAdd(inputString, maxQueryLen):
                return True

            s = e + 1 + snippetMarkerEndLen

        return False

    def generateQueries(self, queriesToGenerate, history, maxQueryLen = MAX_QUERY_LEN):
        """
        parses Bing news page and generates a set of unique queries to run on Bing
        A query is considered to be unique if it distinguishes from any other query at
        least in a meaning letter. Where meaning letter is any ASCII character, but
        terminators (space, comma, colon, etc.)

        Url good enough to get Bing news
        http://www.bing.com/news?q=world+news

        param queriesToGenerate the number of queries to return
        param history a set of previous searches
        param maxQueryLen the maximum query length

        returns a set of queries - self.queries
        """
        if queriesToGenerate <= 0:
            raise ValueError("numberOfQueries should be more than 0, but it is %d" % queriesToGenerate)
        self.numberOfQueries = queriesToGenerate

        if history is None or not isinstance(history, set):
            raise ValueError("history is not set or not an instance of set")
        self.history = history

        request = urllib2.Request(url = BING_NEWS_URL, headers = self.bingRewards.httpHeaders)
        with self.bingRewards.opener.open(request) as response:
            newsPage = helpers.getResponseBody(response)

        if newsPage is None: raise TypeError("newsPage is None")
        if newsPage.strip() == "": raise ValueError("newsPage is empty")

        self.rewardType = bfp.Reward.Type.SEARCH_PC
        startMarker = '<div class="NewsResultSet'
        s = newsPage.find(startMarker)
        if s == -1:
            self.rewardType = bfp.Reward.Type.SEARCH_MOBILE
            startMarker = '<div class="mpage'
            s = newsPage.index(startMarker)

        s += len(startMarker)
        s = newsPage.index(">", s)
        s += 1

        if self.rewardType == bfp.Reward.Type.SEARCH_MOBILE:
            endMarker = '<div id="CntFtr"'
        else:
            endMarker = '<div class="RightRail"'

        e = newsPage.index(endMarker, s)

        self.__generateQueries(newsPage[s:e], maxQueryLen)

        return self.queries
