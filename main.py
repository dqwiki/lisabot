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
lastlnk=""

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
		time.sleep(10)
def main():
        readbuffer=''
        ## Infinte loop - command parsing.
        log = "log.txt"
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
                                except Exception:
                                        pass
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
                        elif line2[1] == "NOTICE" and line2[6] == "identified":
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
                                        thread.start_new_thread(commandparser,(line, line2, nick, chan, host, ld, s2))
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

def commandparser(line, line2, nick, chan, host, lockdown, s2):
	if line2[1] == "PRIVMSG" and (line2[3].startswith(":!") or line2[3].startswith(":.")):
		command = string.lower(line2[3][2:])
		thread.start_new_thread(meta_reporting,(line2, nick, chan, command))
		authorization = cparser.authtest(host, chan, "no")
		if command != "null" and lockdown != "true":
			 cparser.main(command, line, line2, nick, chan, host, authorization, notice, say, reply, s, s2)

def notice(nick, msg):
    s.send("NOTICE %s :%s\r\n" % (nick, msg))
    print "   NOTICE %s :%s" % (nick, msg)

def say(msg, chan=CHANS[0]):
    s.send("PRIVMSG %s :%s\r\n" % (chan, msg))
    print "   PRIVMSG %s :%s" % (chan, msg)
	
def reply(msg, chan=CHANS[0], nick=""):
   s.send("PRIVMSG %s :\x02%s:\x0F %s\r\n" % (chan, nick, msg))
   print "   PRIVMSG %s :%s: %s" % (chan, nick, msg)

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


def tellFreenode(msg):
        if "#en.wikipedia :" in msg: msg = string.replace(msg, "#en.wikipedia :", "\x02English Wikipedia:\x0F ")
        if "#simple.wikipedia :" in msg: msg = string.replace(msg, "#simple.wikipedia :", "\x02Simple Wikipedia:\x0F ")
        if "#commons.wikimedia :" in msg: msg = string.replace(msg, "#commons.wikimedia :", "\x02Wikimedia Commons:\x0F ")
        if "#meta.wikimedia :" in msg: msg = string.replace(msg, "#meta.wikimedia :", "\x02Meta Wiki:\x0F ")
        if "Special:Log/rights" in msg:msg = string.replace(msg, "rights", "Changed Userrights")
        if "Special:Log/newusers" in msg:msg = string.replace(msg, "create2", "Created Account Via Email")
        if "Special:Log/block" in msg:msg = string.replace(msg, "reblock", "Changed Block Settings")
        msg = string.replace(msg, "DeltaQuadBot", "DQB")
        msg = string.replace(msg, "DeltaQuad", "DQ")
        if 'Wikipedia:Abuse' in msg or 'Wikipedia talk:Abuse' in msg or ('Special:Log/block' in msg and 'Long-term abuse' in msg):
                msg = string.replace(msg, "#en.wikipedia :", "\x02English Wikipedia:\x0F ")
                print msg
                say(msg, "#wikipedia-en-abuse")
                time.sleep(0.5)
        if 'DeltaQuad' in msg or 'Vandalism information' in msg or 'Jamesofur' in msg or 'Wikipedia:Usernames for administrator attention/Bot' in msg:
                print msg
                say(msg, "##DeltaQuad-RC")
                time.sleep(0.5)
        if 'Special:Log/block' in msg and '[[WP:Vandalism|Vandalism]]' not in msg and '[[WP:Vandalism-only account|Vandalism-only account]]' not in msg and 'ProcseeBot' not in msg:
                print msg
                say(msg, "##DeltaQuad-RC-block")
                time.sleep(0.5)
        if 'Special:Log/delete' in msg and 'revision' in msg:
                print msg
                say(msg, "##DeltaQuad-RC-revdel")
                time.sleep(0.5)
        if 'Sockpuppet investigations' in msg and 'bot' not in msg and 'Special:Log/block' not in msg:
                print msg
                say(msg, "#wikipedia-en-spi")
                time.sleep(0.5)
        if 'Special:Log/newusers' in msg:
                print msg
                say(msg, "##DeltaQuad-RC-newacc")
                time.sleep(0.5)
        if 'setstatus' in msg or 'Special:Log/rights' in msg or 'gblock2' in msg:
                msg = string.replace(msg, "\x02Meta Wiki:\x0F ", "\x02Global Action:\x0F ")
                msg = string.replace(msg, "\x02Simple Wikipedia:\x0F ", "\x02SMWP Rights Change:\x0F ")
                msg = string.replace(msg, "\x02English Wikipedia:\x0F ", "\x02ENWP Rights Change:\x0F ")
                msg = string.replace(msg, "setstatus", "Global Account Lock/Unlock")
                msg = string.replace(msg, "gblock2", "Global Block")
                if "Special:Log/delete" in msg:msg = string.replace(msg, "revision", "Changed Revsion Visability", 1)
                print msg
                say(msg, "##DeltaQuad-RC")
                time.sleep(0.5)
if __name__ == "__main__":
    run()