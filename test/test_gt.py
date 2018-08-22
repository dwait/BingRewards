#!/usr/bin/python2

import os
import sys
import random

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "pkg/queryGenerators"))

from googleTrends import queryGenerator

if __name__ == '__main__':
    G = queryGenerator("nothing")
    T = queryGenerator("nothing2")
    history = set("nothing")
    #print "all queries len:", len(G.allQueries)
    #print "unused queries len:", len(G.unusedQueries)
    #print "--Running 1st query"
    set1 = T.generateQueries(100,history)
    print "set size", len(set1)
    print "all queries len:", len(G.allQueries)
    print "unused queries len:", len(G.unusedQueries)
    size = len(set1)
    set1 = set(random.sample(set1, len(set1)-5))
    print "after random set1 size:", len(set1)
    print "using set1 as a history for another search"
    print "--Running 2nd query"
    queries = G.generateQueries(100,set1)
    print "set size", len(queries)
    print "all queries len:", len(G.allQueries)
    print "unused queries len:", len(G.unusedQueries)
    if set1.isdisjoint(queries):
        print "No history results are in the final set"
    print "--Running 3nd query"
    queries2 = G.generateQueries(100,history)
    print "set size", len(queries2)
    print "all queries len:", len(G.allQueries)
    print "unused queries len:", len(G.unusedQueries)
    print "Shared entries between query2 and 3:", len(queries.intersection(queries2))
    print "--Running 4th query"
    queries3 = G.generateQueries(125,history)
    print "set size", len(queries3)
    print "all queries len:", len(G.allQueries)
    print "unused queries len:", len(G.unusedQueries)

