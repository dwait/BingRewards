# BingRewards
## About
BingRewards is an automated point earning script that works with Bing.com to earn points that can be redeemed for giftcards.

## Requirements
Python 2.7+

## Running The Script
Copy *config.xml.dist* to *config.xml*  
Enter accounts in `<accounts>` section.  
Ensure `<events>` match accounts or are commented out.

Linux/Mac
```bash
$ cd path/to/bingrewards
$ ./main.py
```
Windows
```
> cd path\to\bingrewards
> python main.py
```
Docker

A Dockerfile is included in this repository. You can build your local version as follows:
```
docker build -t bingrewards .
```
Once that's built you can run it as follows (make sure you adjust the path to your `config.xml`)
```
docker run -it --rm -v `pwd`/config.xml:/usr/src/app/config.xml bingrewards
```

## Config

### General
betweenQueriesInterval: Number of seconds between queries  
betweenQueriesSalt: Random number of seconds added between queries  
betweenAccountsInterval: Number of seconds between accounts  
betweenAccountsSalt: Random number of seconds added between accounts  
addSearchesDesktop: Number of extra desktop searches  
addSearchesDesktopSalt: Random number of added desktop searches  
addSearchesMobile: Number of extra mobile searches  
addSearchesMobileSalt: Random number of added mobile searches  

### Accounts
You can have as many account tags as you need.  
**Note**: User-Agent fields are optional. If omitted a random User-Agent will be selected. Use caution when entering a custom User-Agent. If User-Agent is not associated with a common browser Bing might flag you as a bot.  
**Note**: Two-Factor Authentication (2FA) is not supported.
```xml
<account disabled="(true|false)">
    <login>email@example.org</login>
    <password>passwordhere</password>
    <ua_desktop><![CDATA[YOUR DESKTOP USER AGENT HERE]]></ua_desktop>
    <ua_mobile><![CDATA[YOUR MOBILE USER AGENT HERE]]></ua_mobile>
</account>
```

### Query Generators
- **bing**: Uses today's bing news page. Generates terms which may be partial words.
- **googleTrends**: Uses today's google trends, and google suggested searches. This generator generates whole words, generally consistent with a search syntax. These terms are anything trending and can be NSFW or terms for illegal items.
- **wikipedia**: Uses today's wikipedia. Generates terms with whole words.

### Events
onError: Defines what the script should do when an error occurs during processing an account.  
onComplete: Defines how the script should behave when it completes processing an account.  
onScriptComplete: A special event which occurs only once when the script finishes executing.  
onScriptFailure: A special event which occurs only once and if the script fails with exception some time after successfully loading the config.

## Automating
Linux/Mac: Create cron job  
Replace `LOCAL_CONFIG_DIR` setting with the path to your Bing Rewards folder.  
You will also need to update the paths in the command to point to your Bing Rewards folder.
The below cronjob will run at 1 am + random(120 minutes).
It will save the console output to to a log file
```bash
SHELL=/bin/bash
PATH=/usr/bin:$PATH
LOCAL_CONFIG_DIR=/home/bingrewards/etc

0   1   *   *   *   sleep $(($RANDOM \% 120))m && python2 /home/bingrewards/bin/main.py 2>&1 | gzip > /home/bingrewards/var/log/bingrewards/`date "+\%Y-\%m-\%dT\%H:\%M:\%S"`.log.gz
```
Windows: Use build in Task Scheduler

## References
- For more information, including how to use this, please, take a look at my blog post:
[here](http://sealemar.blogspot.com/2012/12/bing-rewards-automation.html)
- To find out how to convert Bing Rewards points to cash, read my second post in this series:
[here](http://sealemar.blogspot.com/2013/04/bing-rewards-points-to-cash.html)
- [Bing Rewards Automation version 2.0](http://sealemar.blogspot.com/2013/06/bing-rewards-automation-version-2.html)
- [Bing Rewards Automation version 3.0](http://sealemar.blogspot.com/2013/10/bing-rewards-automation-version-30.html) -- _added events support - notifications and retries_
- [Configuration for Bing Rewards Automation script](http://sealemar.blogspot.com/2013/10/configuration-for-bing-rewards.html)
- [Bing Rewards Automation script: Unix Cron](http://sealemar.blogspot.com/2013/10/bing-rewards-automation-script-unix-cron.html)
- [Troubleshooting guide](http://sealemar.blogspot.com/2014/06/troubleshooting-bing-rewards-automation.html)
