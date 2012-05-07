# -*- coding: utf-8  -*-
### LisaBot
## A copy of the copyright statement is in the configuration file: config.py
## Import basics.
import sys, socket, string, time, codecs, os, traceback, thread, re, urllib

## Import our functions.
import config

## Import our external command library.
import commands as cparser

from datetime import datetime

## Set up constants.
HOST, PORT, NICK, IDENT, REALNAME, CHANS, REPORT_CHAN, WELCOME_CHAN, META_CHAN, HOST2, PORT2, CHAN2, BOT, OWNER, PASS = config.host, config.port, config.nick, config.ident, config.realname, config.chans, config.report_chan, config.welcome_chan, config.meta_chan, config.host2, config.port2, config.chan2, config.bot, config.owner, config.password

ld="false"

commandList = cparser.get_commandList()

startup = "1"

## Connect to IRC.
s=socket.socket()
s2=socket.socket()
s.connect((HOST, PORT))
s.send("NICK %s\r\n" % NICK)
print "   NICK %s" % NICK
s.send("USER %s %s bla :%s\r\n" % (IDENT, HOST, REALNAME))
print "   USER %s %s bla :%s" % (IDENT, HOST, REALNAME)

def run():
	while 1:
		try:
                        main()
		except Exception:
			pass
		time.sleep(15)
def main():
        readbuffer=''
        ## Infinte loop - command parsing.
        lastlink = 'User:DQ'
        thread.start_new_thread(editreport,())
        while 1:
                WHOISSERV = False
                readbuffer=readbuffer+s.recv(1024)
                temp=string.split(readbuffer, "\n")
                readbuffer=temp.pop()
                for line in temp:
                        line2=string.rstrip(line)
                        line2=string.split(line2)
                        if line2[1] == "PRIVMSG": # If it's a privmsg...
                                nick = re.findall(":(.*?)!", line2[0]) # Calculate the nick.
                                nick = nick[0]
                                host = re.findall("@(.*?)\Z", line2[0]) # Calculate the nick.
                                host = host[0]
                                chan = line2[2] # And the channel.
                                if chan == NICK:
                                        chan = nick
                        elif line2[0] == "PING":
                                msg = "PONG %s" % line2[1]
                                s.send(msg + "\r\n")
                                print "   %s" % msg
                        elif line2[1] == "001":
                                msg = "PRIVMSG NICKSERV :IDENTIFY LisaBot %s" % PASS
                                s.send(msg + "\r\n")
                                print "   %s" % msg
                        elif line2[1] == "JOIN" and line2[2][1:] == WELCOME_CHAN:
                                try:
                                        host = re.findall("@(.*?)\Z", line2[0])
                                        nick = re.findall(":(.*?)!", line2[0])
                                        if host[0].startswith("gateway/web/freenode"):
                                                if welcome(None):
                                                        say("Welcome %s! Just ask your question below; a !clerk will be right with you." % nick[0], WELCOME_CHAN)
                                                        say("\x0302Newbie welcomed:\x0301 \x02%s\x0F was welcomed into \x02%s\x0F." % (nick[0], REPORT_CHAN), META_CHAN)
                                                        notice("##LisaBot","Please Remember to start me up!")
                                except Exception:
                                        pass
                        elif line2[1] == "MODE" and line2[2] == "#wikipedia-en-spi" and line2[3] == "+v" and line2[0] == ":ChanServ!ChanServ@services.":
                                try:
                                        nick = line2[4]
                                        if nick == NICK: continue
                                        number = unicode(int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:Abuse_response_-_Waiting_for_Investigation&cmlimit=500").read()))))
                                        num2 = unicode(int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:Abuse_response_-_Open&cmlimit=500").read()))))
                                        aggregate = int(number) + int(num2)
                                        if nick == NICK: continue
                                        import time
                                        print "Start opening"
                                        cur = int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:SPI_requests_for_pre-CheckUser_review&cmlimit=500").read())))
                                        time.sleep(.25)
                                        cuendorse = int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:SPI_cases_awaiting_a_CheckUser&cmlimit=500").read())))
                                        time.sleep(.25)
                                        inprogress = int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:SPI_cases_currently_in_progress&cmlimit=500").read())))
                                        time.sleep(.25)
                                        waitclose = int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:SPI_cases_awaiting_administration&cmlimit=500").read())))
                                        time.sleep(.25)
                                        close = int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:SPI_cases_pending_close&cmlimit=500").read())))
                                        time.sleep(.25)
                                        admin = int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:SPI_requests_needing_an_Administrator&cmlimit=500").read())))
                                        time.sleep(.25)
                                        print "Send Msg"
                                        notice(nick, "SPI Status: CU Request - %s, CU Endorse - %s, CU in progress - %s, Checked/Actioned/Open - %s, Archive - %s, Need admin - %s" % (cur, cuendorse, inprogress, waitclose, close, admin))
                                except:
                                        print traceback.format_exc()
                        elif line2[1] == "MODE" and line2[2] == REPORT_CHAN and line2[3] == "+v" and line2[0] == ":ChanServ!ChanServ@services.":
                                try:
                                        nick = line2[4]
                                        if nick == NICK: continue
                                        number = unicode(int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:Abuse_response_-_Waiting_for_Investigation&cmlimit=500").read()))))
                                        num2 = unicode(int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:Abuse_response_-_Open&cmlimit=500").read()))))
                                        aggregate = int(number) + int(num2)
                                        if nick == NICK: continue
                                        if aggregate == 0:
                                                stat = "is \x02\x0303clear\x0301\x0F"
                                        elif aggregate < 2:
                                                stat = "has a \x0312small backlog\x0301"
                                        elif aggregate < 4:
                                                stat = "has an \x0307average backlog\x0301"
                                        elif aggregate < 6:
                                                stat = "is \x0304backlogged\x0301"
                                        elif aggregate < 8:
                                                stat = "is \x02\x0304heavily backlogged\x0301\x0F"
                                        else:
                                                stat = "is \x02\x1F\x0304severely backlogged\x0301\x0F"
                                        notice(nick, "\x02Current status:\x0F Abuse Response %s (\x0302Investigator Needed\x0301: \x0305%s\x0301; \x0302Open\x0301: \x0305%s\x0301; )" % (aggregate, number, num2))
                                        say("\x0302Member welcomed:\x0301 \x02%s\x0F was welcomed into \x02%s\x0F." % (nick, REPORT_CHAN), META_CHAN)
                                except Exception:
                                        print traceback.format_exc()
                        elif line2[1] == "NOTICE" and "identified" in line2:
                                print "START"
                                for chan in CHANS:
                                        msg = "JOIN %s" % chan
                                        s.send(msg + "\r\n")
                                        print "   %s" % msg
                        if line2[1] == "PRIVMSG":
                                try:
                                        if "kicks %s" % NICK in ' '.join(line2):
                                                say("owowowowowow", chan)
                                                time.sleep(0.5)
                                                reply("How dare you!?", chan, nick)
                                        if "punches %s" % NICK in ' '.join(line2):
                                                say(":x", chan)
                                                time.sleep(0.5)
                                                say("\x01ACTION retaliates with a roundhouse kick.\x01", chan)
                                        thread.start_new_thread(commandparser,(line, line2, nick, chan, host, ld, s2, lastlink))
                                except Exception:
                                        trace = traceback.format_exc() # Traceback.
                                        print trace # Print.
                                        lines = list(reversed(trace.splitlines())) # Convert lines to process traceback....
                                        report2 = [lines[0].strip()]
                                        for line in lines: 
                                                line = line.strip()
                                                if line.startswith('File "/'): 
                                                        report2.append(line[0].lower() + line[1:])
                                                        break
                                        else: report2.append('source unknown')
                                        say(report2[0] + ' (' + report2[1] + ')', chan)

def meta_reporting(line2, nick, chan, command):
	if command not in commandList.keys():
		return
	command = commandList[command]
	params = ' '.join(line2[4:])
	if chan != nick:
		channel = "\x02%s\x0F" % chan
	else:
		channel = "a private message"
	if params:
		msg = "\x0302Command executed:\x0301 \x02%s\x0F used command \x02%s\x0F in %s with parameters \"\x02%s\x0F\"." % (nick, command, channel, params)
	else:
		msg = "\x0302Command executed:\x0301 \x02%s\x0F used command \x02%s\x0F in %s." % (nick, command, channel)
	say(msg, META_CHAN)

def commandparser(line, line2, nick, chan, host, lockdown, s2, lastlink):
	if line2[1] == "PRIVMSG" and (line2[3].startswith(":!") or line2[3].startswith(":.")):
		command = string.lower(line2[3][2:])
		if command == "refreshrc":
                        actionlevel = cparser.authtest(host, chan)
                        if actionlevel[4]==1:
                                return
                        else:
                                refreshRClist()
                                reply("RC List refreshed.", chan, nick)
                        return
		thread.start_new_thread(meta_reporting,(line2, nick, chan, command))
		authorization = cparser.authtest(host, chan)
		if command != "null" and lockdown != "true":
			 cparser.main(command, line, line2, nick, chan, host, authorization, notice, say, reply, s, s2, lastlink)

def notice(nick, msg):
    s.send("NOTICE %s :%s\r\n" % (nick, msg))
    print "   NOTICE %s :%s" % (nick, msg)

def say(msg, chan=CHANS[0]):
    s.send("PRIVMSG %s :%s\r\n" % (chan, msg))
    print "   PRIVMSG %s :%s" % (chan, msg)
	
def reply(msg, chan=CHANS[0], nick=""):
   say(msg, chan)

def editreport():
        s2.connect((HOST2, PORT2))
        s2.send("NICK %s\r\n" % NICK)
        print "   NICK %s" % NICK
        s2.send("USER %s %s bla :%s\r\n" % (IDENT, HOST2, REALNAME))
        print "   USER %s %s bla :%s" % (IDENT, HOST2, REALNAME)
        readbuffer=''
        ## Infinte loop - command parsing.
        while 1:
                readbuffer=readbuffer+s2.recv(1024)
                temp=string.split(readbuffer, "\n")
                readbuffer=temp.pop()
                for line in temp:
                        line2=string.rstrip(line)
                        line2=string.split(line2)
                        if line2[1] == "PRIVMSG":
                                try:
                                        tellFreenode(' '.join(line2[2:]))
                                except BaseException:
                                        import traceback
                                        print traceback.format_exc()
                        elif line2[0] == "PING":
                                msg = "PONG %s" % line2[1]
                                s2.send("%s\r\n" % msg)
                                print "   %s" % msg
                        elif line2[1] == "376":
                                msg = "PING :irc.wikimedia.org"
                                s2.send("%s\r\n" % msg)
                                print "   %s" % msg
                                CHAN2 = "#en.wikipedia"
                                msg = "JOIN %s" % CHAN2
                                s2.send("%s\r\n" % msg)
                                print "   %s" % msg
                                CHAN2 = "#commons.wikimedia"
                                msg = "JOIN %s" % CHAN2
                                s2.send("%s\r\n" % msg)
                                print "   %s" % msg
                                CHAN2 = "#simple.wikipedia"
                                msg = "JOIN %s" % CHAN2
                                s2.send("%s\r\n" % msg)
                                print "   %s" % msg
                                CHAN2 = "#meta.wikimedia"
                                msg = "JOIN %s" % CHAN2
                                s2.send("%s\r\n" % msg)
                                print "   %s" % msg


def refreshRClist():
        import MySQLdb, traceback
        db = MySQLdb.connect(db="u_deltaquad_rights", host="sql", read_default_file="/home/deltaquad/.my.cnf")
        db.query("SELECT * FROM rcstalklist;")
        r = db.use_result()
        global rcstalk
        rcstalk = r.fetch_row(maxrows=0)
        
        db.query("SELECT * FROM rcblacklist;")
        r = db.use_result()
        global blacklist
        blacklist = r.fetch_row(maxrows=0)

def tellFreenode(msg):
        alreadyprint = ""
        if "#en.wikipedia :" in msg: msg = string.replace(msg, "#en.wikipedia :", "\x02English Wikipedia:\x0F ")
        if "#simple.wikipedia :" in msg: msg = string.replace(msg, "#simple.wikipedia :", "\x02Simple Wikipedia:\x0F ")
        if "#commons.wikimedia :" in msg: msg = string.replace(msg, "#commons.wikimedia :", "\x02Wikimedia Commons:\x0F ")
        if "#meta.wikimedia :" in msg: msg = string.replace(msg, "#meta.wikimedia :", "\x02Meta Wiki:\x0F ")
        if "Special:Log/rights" in msg:msg = string.replace(msg, "rights", "Changed Userrights")
        if "Special:Log/newusers" in msg:msg = string.replace(msg, "create2", "Created Account Via Email")
        if "Special:Log/block" in msg:msg = string.replace(msg, "reblock", "Changed Block Settings")
        for line in rcstalk:
                method = line[2]
                page = msg.split("\x0314]]")[0]
                page = page.split("[[\x0307")[1]
                user = msg.split("* \x0303")[1]
                user = user.split("* (")[0]
                try:summary = msg.split(") ")[1]
                except:summary = msg.split("\":")[1]
                if method == "user" and not None == (re.search(line[0].lower(),user.lower())):
                        print msg
                        for bline in blacklist:
                                if bline[0].lower() in page.lower() and bline[1] == line[1]:
                                        return
                        if not line[1] in alreadyprint:
                                firstmsg = msg.split(":")[0]
                                secondmsg = msg.split(":")[1:]
                                msg = firstmsg + " \x0304(Matched user: " + line[0].lower + ")\x0301" + secondmsg
                                say(msg, line[1])
                        time.sleep(0.5)
                        alreadyprint = alreadyprint + "," + line[1]
                if method == "page" and not None == (re.search(line[0].lower(),page.lower())):
                        print msg
                        for bline in blacklist:
                                if bline[0].lower() in page.lower() and bline[1] == line[1]:
                                        return
                        if not line[1] in alreadyprint:
                                firstmsg = msg.split(":")[0]
                                secondmsg = msg.split(":")[1:]
                                msg = firstmsg + " \x0304(Matched page: " + line[0].lower() + ")\x0301" + secondmsg
                                say(msg, line[1])
                        time.sleep(0.5)
                        alreadyprint = alreadyprint + "," + line[1]
                if method == "summary" and not None == (re.search(line[0].lower(),summary.lower())):
                        print msg
                        for bline in blacklist:
                                if bline[0].lower() in summary.lower() and bline[1] == line[1]:
                                        return
                        if not line[1] in alreadyprint:
                                firstmsg = msg.split(":")[0]
                                secondmsg = msg.split(":")[1:]
                                msg = firstmsg + " \x0304(Matched summary: " + line[0].lower() + ")\x0301" + secondmsg
                                say(msg, line[1])
                        time.sleep(0.5)
                        alreadyprint = alreadyprint + "," + line[1]
                        continue
                #if not line[0].lower() in msg.lower():
                       #continue
                        
refreshRClist()
        
if __name__ == "__main__":
    run()
