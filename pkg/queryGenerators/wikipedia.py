#!/usr/bin/env python2

#
# Wikipedia queries generator
# developed by Alex Mayer (2014)
#

import re
import helpers
import urllib2
from random import randint, shuffle
from datetime import date
from bingRewards import BingRewards

MONTH_NAMES = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
QUERY_URL = "https://en.wikipedia.org/wiki/{0}_{1}?action=raw".format(MONTH_NAMES[date.today().month - 1], date.today().strftime("%d").strip("0"))
WIKIPEDIA_SECTION_PATTERN = re.compile(r'==([^\n]+)==\n(.+?)\n\n', re.S)
WIKIPEDIA_LINK_PATTERN = re.compile(r'\[\[(?:[^|\]]*\|)?([a-zA-Z\s]+?)\]\]')
"""
higher weight = higher priority(relatively)
assuming "events" weight is 4 and "births" weight is 1:
if "events" section has 20 links and "births" section has 20 links
"events" section will be favored 4 to 1

with the same weights:
if "events" has 20 links and "births" has 40 links
"events" will be favored 2 to 1

How the math works:
"events" weight is 4 and has 20 links
each link will be added to the search pool 4 times generating 80 event links

after a link is chosen from the pool to be returned as a query
all other instances of the link are removed
"""
DEFAULT_SECTION_WEIGHT = 2
DEFAULT_SECTION_WEIGHTS = {
    "events": 4,
    "holidays and observances": 4,
    "births": 1,
    "deaths": 1
}

class queryGenerator:
    def __init__(self, br):
        """
        param br is a pointer to the calling class bingRewards (used for variables)
        """
        if br is None or not isinstance(br, BingRewards):
            raise ValueError("br is not set or is not an instance of BingRewards")
        self.bingRewards = br

    def generateQueries(self, queriesToGenerate, history, maxQueryLen = None):
        """
        Parses the current days wikipedia.com page and generates queries
        from the links on the page.

        param queriesToGenerate the number of queries to return
        param history a set of previous searches
        param maxQueryLen the maximum query length

        returns a set of queries - self.queries
        """
        if queriesToGenerate <= 0:
            raise ValueError("numberOfQueries should be more than 0, but it is %d" % queriesToGenerate)
        if history is None or not isinstance(history, set):
            raise ValueError("history is not set or not an instance of set")

        request = urllib2.Request(url = QUERY_URL, headers = self.bingRewards.httpHeaders)
        with self.bingRewards.opener.open(request) as response:
            page = helpers.getResponseBody(response)

        # check that the page has content
        if page.strip() == "":
            raise ValueError("Wikipedia page is empty")

        # convert history to lowercase
        history = [x.strip().lower() for x in history]

        # get sections of the page (ie. Events, Births, Deaths, Holidays)
        rawSections = WIKIPEDIA_SECTION_PATTERN.findall(page)

        if len(rawSections) == 0:
            raise ValueError("Wikipedia page is empty")

        # a list of search terms
        searchTerms = []

        for sectionName, conts in rawSections:
            section = sectionName.lower()
            # skip unwanted sections
            if section in ["external links"]:
                continue

            # extract search terms
            rawTerms = WIKIPEDIA_LINK_PATTERN.findall(conts)

            # skip empty sections
            if len(rawTerms) == 0:
                continue

            terms = []
            # check each term against history
            for term in rawTerms:
                # humans search in lowercase
                term = term.lower()
                # check if the term was searched for before
                if term not in history:
                    terms.append(term)

            # entire section is in history... skip it
            if len(terms) == 0:
                continue

            # section search weight
            weight = DEFAULT_SECTION_WEIGHT
            if section in DEFAULT_SECTION_WEIGHTS:
                weight = DEFAULT_SECTION_WEIGHTS[section]

            # add each search term list the number of weighted times
            for i in range(weight):
                searchTerms.extend(terms)

        # randomize the search terms for good measure
        shuffle(searchTerms)

        queries = set()
        queriesNeeded = queriesToGenerate
        # loop until we have enough queries or run out of things to search for
        while queriesNeeded > 0 and len(searchTerms) > 0:
            ri = randint(0, len(searchTerms) - 1)
            # add current term to queries
            queries.add(searchTerms[ri])
            # remove each instance of current term from searchTerms
            searchTerms = filter(lambda x: x != searchTerms[ri], searchTerms)
            queriesNeeded -= 1

        return queries
