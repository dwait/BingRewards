#!/usr/bin/env python2

#
# developed by Sergey Markelov (2013)
#

"""
Bing dashboard page parser

Usage:
    from bingDashboardParser import Reward, parseDashboardPage
    ...
    bingRewards = BingRewards(FACEBOOK_EMAIL, FACEBOOK_PASSWORD)
    bingRewards.authenticate()
    parseDashboardPage(bingRewards.requestDashboardPage(), BING_URL)
"""

import re
from datetime import datetime
import sys

class Reward:
    "A class to represent a Bing reward"

    class Type:
        class Action:
            PASS   = 0
            INFORM = 1
            HIT    = 2
            SEARCH = 3
            WARN   = 4

            @staticmethod
            def toStr(action):
                actions = ("pass", "inform", "hit", "search", "warn")
                return (actions[action])

        class Col:
            INDEX       = 0
            NAME        = 1
            DESCRIPTION = 2  # optional field, can be set to None
            ISRE        = 3
            ACTION      = 4

        SEARCH_AND_EARN_DESCR_RE = re.compile(r"[Uu]p to (\d+) points? (?:per day|today), (\d+) points? per search")
        SEARCH_AND_EARN_DESCR_RE_MOBILE = re.compile(r"(\d+) points per search on Microsoft Edge mobile app or (\d+) points per search on any other mobile browser, for up to (\d+) mobile searches per day")
        # need to change this to work for hits
        EARN_CREDITS_RE = re.compile("Earn (\d+) credits?")

#       Alias                   Index Reward.name
#                           optional(Reward.description)                         isRe?  Action

        RE_EARN_CREDITS_PASS = (1,    EARN_CREDITS_RE,
                            "Get the best of Bing by signing in with Facebook.", True,  Action.PASS)
        RE_EARN_CREDITS      = (2,    EARN_CREDITS_RE,                     None, True,  Action.HIT)
        SEARCH_MOBILE        = (3,    "Mobile search",                     None, False, Action.SEARCH)
        SEARCH_PC            = (4,    "PC search",                         None, False, Action.SEARCH)
        YOUR_GOAL            = (5,    "Your goal",                         None, False, Action.INFORM)
        MAINTAIN_GOLD        = (6,    "Maintain Gold",                     None, False, Action.INFORM)
        REFER_A_FRIEND       = (7,    "Refer-A-Friend",                    None, False, Action.PASS)
        SEND_A_TWEET         = (8,    "Send a Tweet",                      None, False, Action.PASS)
        RE_EARNED_CREDITS    = (9,    re.compile("Earned \d+ credits?"),   None, True,  Action.PASS)
        COMPLETED            = (10,    "Completed",                        None, False, Action.PASS)
        SILVER_STATUS        = (11,   "Silver Status",                     None, False, Action.PASS)
        INVITE_FRIENDS       = (12,   "Invite friends",                    None, False, Action.PASS)
        EARN_MORE_POINTS     = (13,   "Earn more points",                  None, False, Action.INFORM)
        SEARCH_AND_EARN      = (14,   "Search and earn",                   None, False, Action.SEARCH)
        THURSDAY_BONUS       = (15,   "Thursday bonus",                    None, False, Action.PASS)
        RE_QUIZ              = (16,   re.compile(r"\b[Qq]uiz\b"),          None, True,  Action.PASS)
        SHOP_AND_EARN        = (17,   "Shop & earn",                       None, False, Action.INFORM)

        ALL = (RE_EARN_CREDITS_PASS, RE_EARN_CREDITS, SEARCH_MOBILE, SEARCH_PC, YOUR_GOAL, MAINTAIN_GOLD,
               REFER_A_FRIEND, SEND_A_TWEET, RE_EARNED_CREDITS, COMPLETED, SILVER_STATUS, INVITE_FRIENDS,
               EARN_MORE_POINTS, SEARCH_AND_EARN, THURSDAY_BONUS, RE_QUIZ, SHOP_AND_EARN)

    def __init__(self):
        self.url = ""               # optional
        self.name = ""
        self.progressCurrent = 0    # optional
        self.progressMax = 0        # optional
        self.isDone = False         # optional - is set if progress is "Done"
        self.description = ""
        self.tp = None              # is one of self.Type if set
        self.hitId = None           # only for hits, needed to relay info to verify hit
        self.hitHash = None         # same as above, needed to relay info to verify hit

    def isAchieved(self):
        """
        Returns True if the reward is achieved.
        Applicable only if self.progressMax is not 0
        """
        return (self.isDone or self.progressMax != 0 and self.progressCurrent == self.progressMax)

    def progressPercentage(self):
        if self.progressMax == 0:
            return 0
        else:
            return (float(self.progressCurrent) / self.progressMax * 100)

def parseDashboardPage(page, bing_url):
    """
    Parses a bing dashboard page
    returns a list of Reward objects

    page - bing dashboard page - see the class __doc__ for further information
    bing_url - url of bing main page - generally http://www.bing.com which will be
                added to Reward.url as a prefix if appropriate
    """
    reload(sys)
    sys.setdefaultencoding('utf8')

    if page is None: raise TypeError("page is None")
    if page.strip() == "": raise ValueError("page is empty")

    allRewards = []

    # if this is the new type of dashboard page (there's probably a better way to figure this out)
    if page.find("rewards-oneuidashboard") != -1:
        page = page.split("var dashboard")[1]
        # Rewards can be listed more than once so track here and skip those that are already complete
        allTitles = set()
        for attrPair in page.split(',"'):
            current = attrPair.replace('"','').split(':')
            if current[0] == "title":
                currentTitle = current[1].strip()
                if currentTitle in allTitles:
                    # already have this reward, skip it
                    continue
                else:
                    newRwd = Reward()
                    allTitles.add(currentTitle)
                    validRwd = createRewardNewFormat(page, currentTitle, newRwd)
                    if validRwd:
                       allRewards.append(newRwd)
    #else:
        # unrecognized dashboard

    return allRewards

def checkForHit(currAction, rewardProgressCurrent, rewardProgressMax, searchLink):
    if currAction is not None:
        if rewardProgressCurrent == 0 and rewardProgressMax == 0:
            if currAction.get_text().lower().find('points') != -1:
                try:
                    rewardProgressMax = int(currAction.get_text().split(' ')[0])
                except ValueError:
                    pass
                # Use the button div to determine whether the offer has been completed
                btn = searchLink.find('div', class_='card-button-height text-caption text-align-center offer-complete-card-button-background border-width-2 offer-card-button-background')
                if btn is not None:
                    rewardProgressCurrent = rewardProgressMax
                return [rewardProgressCurrent, rewardProgressMax]

def createReward(reward, rUrl, rName, rPC, rPM, rDesc, hitId=None, hitHash=None):
    reward.url = rUrl.strip().replace(' ','')
    reward.name = rName.strip().encode('latin-1', 'ignore')
    reward.progressCurrent = rPC
    reward.progressMax = rPM
    reward.description = rDesc.strip().encode('latin-1', 'ignore')
    if hitId:
        reward.hitId = hitId
    if hitHash:
        reward.hitHash = hitHash
    if rPC == rPM:
        reward.isDone = True

    for t in Reward.Type.ALL:
        if t[Reward.Type.Col.ISRE]:         # regex
            if t[Reward.Type.Col.NAME].search(reward.name) \
                and ( t[Reward.Type.Col.DESCRIPTION] is None \
                      or t[Reward.Type.Col.DESCRIPTION] == reward.description ):
                            reward.tp = t

        elif t[Reward.Type.Col.NAME].lower() == reward.name.lower() \
                and ( t[Reward.Type.Col.DESCRIPTION] is None \
                      or t[Reward.Type.Col.DESCRIPTION] == reward.description ):
                            reward.tp = t

    # for 'HIT' rewards (10 points) we assume 10 points, higher values won't be triggered
    # To determine whether a hit is already complete, there is logic above to check which div the button uses + the comparison below
    if reward.progressMax == 10 and reward.progressCurrent != 10:
        reward.tp = Reward.Type.RE_EARN_CREDITS

def createRewardNewFormat(page, title, newRwd):
    curDate = datetime.now()
    isValid = True
    rewardURL = ''
    rewardName = ''
    rewardProgressCurrent = 0
    rewardProgressMax = 0
    rewardDescription = ''
    # We're going to use this as at trigger to determine whether to process the reward or throw it out. If there is no "complete" attribute (true/false) then ignore the reward
    hasComplete = -1
    relevantSegment = page[page.index(title):]
    # need the hash for hits but it is outside of the relevant segment so get it here
    hitHash = relevantSegment[relevantSegment.find('hash')+7:]
    hitHash = hitHash[:hitHash.find('","')]
    relevantSegment = relevantSegment[:relevantSegment.index("}")]
    rewardName = cleanString(title)
    # check relevant segment for 'slide_0', if exists switch to slide processing branch - ignoring for now since I'm not sure slides are rewards
    if relevantSegment.find("slide_") == -1:
        for attrPair in relevantSegment.split(',"'):
            current = attrPair.replace('"','').split(':')
            attrType = current[0].strip().replace('"','')
            # usually just 'description' but some rewards use slide prefix ex: slide_1_description, slide_2_description. Might be better to use regex here
            if attrType == "description":
                rewardDescription = cleanString(current[1])
            if attrType == "progress":
                rewardProgressCurrent = int(cleanString(current[1]))
            if attrType == "max":
                rewardProgressMax = int(cleanString(current[1]))
            if attrType == "destination":
                # since we are splitting on colons the URL is getting split. Need to put it back together here
                if len(current[1]) > 0:
                    if current[1] == 'https' or current[1] == 'http':
                        rewardURL = cleanString(current[1]+':'+current[2])
                    else:
                        rewardURL = cleanString(current[1])
            if attrType == "daily_set_date" != -1:
                # if this reward is not for today (sneak peek rewards are tomorrow), we don't want it
                if len(current[1]) > 0:
                    attrDateObj = datetime.strptime(cleanString(current[1]), '%m/%d/%Y')
                    if not (attrDateObj.year == curDate.year and attrDateObj.month == curDate.month and attrDateObj.day == curDate.day):
                        isValid = False
            if attrType == "complete":
                if current[1] == 'True':
                    hasComplete = 1
                if current[1] == 'False':
                    hasComplete = 0
            if attrType == "offerid":
                hitIdentifier = cleanString(current[1])

            if rewardName == "Current day streak":
                hasComplete = 1
                if attrType == "activity_progress":
                    rewardDescription = rewardName
                    rewardProgressCurrent = int(cleanString(current[1]))
                    rewardProgressMax = int(cleanString(current[1]))
                    hitIdentifier = ""

    # if it isn't completable then it probably isn't a reward, so ignore it
    if hasComplete == -1:
        isValid = False
    if isValid:
        createReward(newRwd, rewardURL, rewardName, rewardProgressCurrent, rewardProgressMax, rewardDescription, hitIdentifier, hitHash)
    return isValid

def cleanString(strToClean):
    return strToClean.replace("\u0027","'").replace("\u0026","&")
