#
# Google Trends queries generator
# Developed by Sangdrax (2014)
#

# This generator generates whole words, generally consistent
# with a search syntax.  These terms are anything trending
# and can be NSFW or terms for illegal items.

import random
from xml.etree import ElementTree

from six.moves import urllib

TRENDSURL = "http://www.google.com/trends/hottrends/atom/feed?pn=p1"
SUGGESTURL = "http://suggestqueries.google.com/complete/search?output=toolbar&hl=en&q="
MAX_QUERY_LEN = 50

class queryGenerator:

    def __init__(self, br):
        self.br = br
        self.allQueries = self.__pullAll()
        self.unusedQueries = self.allQueries.copy()

    def __pullAll(self):
        result = self.__trendQueries()
        tmp = result.copy()
        for term in tmp:
            suggestSet = self.__suggestQueriesSingle(term)
            result.update(suggestSet)
        return result.copy()

    def __readXML(self,URL):
        response = urllib.request.urlopen(URL)
        try:
            return ElementTree.parse(response)
        except:
            return None
        finally:
            response.close()

    def __trendQueries(self):
        generated = set()
        tree = self.__readXML(TRENDSURL)
        if tree is None: raise TypeError("trend could not parse XML")

        for item in tree.iter("item"):
            title = item.find('title').text
            desc = item.find('description').text
            generated.add(title.strip().lower())
            if desc:
                subDesc = desc.split(',')
                subDesc = subDesc if len(subDesc) <= 10 else random.sample(subDesc, 10)
                for sitem in subDesc:
                    generated.add(sitem.strip().lower())
        return generated

    def __suggestQueriesSingle(self,term):
        suggestions = set()
        formatted = urllib.parse.quote_plus(term.encode('utf-8')) #term.replace(" ","+").encode('ascii', 'ignore')
        URL = SUGGESTURL+formatted
        tree = self.__readXML(URL)
        if tree is not None:
            for item in tree.iter("suggestion"):
                suggestions.add(item.get('data').lower())
        return suggestions

    def generateQueries(self, queriesToGenerate, history, maxQueryLen = MAX_QUERY_LEN):
        """
        parses Google Trends top trends and generates a set of unique queries. If the number
        of queries is not >= the requested number, a google suggestion will be called on all
        terms in the query set.  These suggestions will be added to the set as well.

        param queriesToGenerate the number of queries to return
        param history a set of previous searches
        """
        if queriesToGenerate <= 0: raise ValueError("queriesToGenerate should be more than 0, but it is %d" % queriesToGenerate)
        if history is None or not isinstance(history, set): raise ValueError("history is not set or not an instance of set")

        removedHistory = self.unusedQueries.intersection(history)
        self.unusedQueries -= history
        if queriesToGenerate > len(self.unusedQueries):
            self.unusedQueries = self.__pullAll()
            if queriesToGenerate > len(self.unusedQueries): raise ValueError("too many queries requested")

        final = random.sample(self.unusedQueries, queriesToGenerate)
        finalSet = set(final)
        self.unusedQueries -= finalSet
        self.unusedQueries.update(removedHistory)
        return finalSet.copy()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
