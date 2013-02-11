##LisaBot - IRC Bot
##Copyright (C) 2012 DeltaQuad
##This program is free software: you can redistribute it and/or modify
##it under the terms of the GNU General Public License as published by
##the Free Software Foundation, either version 3 of the License, or
##(at your option) any later version.
##This program is distributed in the hope that it will be useful,
##but WITHOUT ANY WARRANTY; without even the implied warranty of
##MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##GNU General Public License for more details.
##You should have received a copy of the GNU General Public License
##along with this program.  If not, see <http://www.gnu.org/licenses/>.

# -*- coding: utf-8  -*-

## Import basics.
import sys, socket, string, time, codecs, os, traceback, thread, re, urllib, web, math, unicodedata

## Import our functions.
import config, time

## Set up constants.
HOST, PORT, NICK, IDENT, REALNAME, CHANS, REPORT_CHAN, WELCOME_CHAN, META_CHAN, HOST2, PORT2, CHAN2, BOT, OWNER, PASS = config.host, config.port, config.nick, config.ident, config.realname, config.chans, config.report_chan, config.welcome_chan, config.meta_chan, config.host2, config.port2, config.chan2, config.bot, config.owner, config.password

KEY=config.key

## New permissions systems
## Blocked, Voice, Ops, Secure, Dev
nodev="Access Denied, you need Developer permissions to execute this action."
nosecure="Access Denied, you need Secure permissions or above to execute this action."
noop="Access Denied, you need Op permissions or above to execute this action."
novoice="Access Denied, you need Voice permissions or above to execute this action."
def permlevel(level,need):
        if level == 'block' and need=='block':return True
        if level == 'block':return False
        if level == 'dev':return True
        if level == 'secure' and not need=='dev':return True
        if level == 'op' and not (need=='secure' or need=='dev'):return True
        if level == 'voice' and not (need=='secure' or need=='dev' or need=='op'):return True
        return False
def authdb(host, chan, need, local=False):
        if host == '@wikipedia/DeltaQuad':return True
        #Global first, then local
        if local:
                try:f = open('perms-'+chan+'.txt', 'r')
                except IOError:return False
        if not local:
                try:f = open('perms-global.txt', 'r')
                except IOError:return False
        text = f.read()
        f.close()
        for line in text:
                line=line.split(',')
                if line[0] == host:
                        result=permlevel(line[1],need)
                        if not local and not result:return authdb(host,chan,need,True)
                        return result
        return False
def authtest(host, chan, need):
        if not "@" in host:host= "@" + host
        print "AuthDB"
        try:return authdb(host, chan, need)
	except:return False
def get_commandList():
	return {
	'join': 'join',
	'part': 'part',
		'leave': 'part',
	'restart': 'restart',
	'quit': 'quit',
		'die': 'quit',
		'suicide': 'quit',
	'langcode': 'langcode',
		'lang': 'langcode',
	'number': 'number',
		'count': 'number',
		'num': 'number',
        'cases': 'number',
	'nick': 'nick',
	'promote': 'promote',
	'demote': 'demote',
	'voice': 'voice',
	'devoice': 'devoice',
	'trout': 'trout',
		'fish': 'trout',
    'request': 'request',
    	'page': 'request',
	'kill': 'kill',
		'destroy': 'kill',
		'murder': 'kill',
	'commands': 'commands',
	'help': 'help',
		'doc': 'help',
		'documentation': 'help',
	'reminder': 'reminder',
		'remind': 'reminder',
    'ban': 'ban',
    'kick': 'kick',
    'unban': 'unban',
    'kickban': 'kickban',
    'quiet': 'quiet',
    'unquiet': 'unquiet',
    'sayhi': 'sayhi',
    'globalmsg': 'globalmsg',
    'stalk': 'stalk',
    'unstalk': 'unstalk',
    'hide': 'hide',
    'unhide': 'unhide',
    'blockinfo': 'blockinfo',
    'ipinfo': 'ipinfo',
    'pull': 'pull',
    'chan': 'chan',
    'myhost': 'myhost',
    'git': 'git',
    	'github': 'git',
    'msg': 'msg',
    'me': 'me',
    'mode': 'mode',
    'startup': 'startup',
    'geolocate': 'geolocate',
    	'geo': 'geolocate',
    'sql': 'sql',
    	'perms': 'sql'
	}

def main(command, line, line2, nick, chan, host, notice, say, reply, s, s2, lastlink):
	try:
		parse(command, line, line2, nick, chan, host, notice, say, reply, s, s2, lastlink)
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

def parse(command, line, line2, nick, chan, host, notice, say, reply, s, s2, lastlink):
	try:
                if authtest(host, chan, 'block'):return
        except:
                import traceback
                trace = traceback.format_exc() # Traceback.
		print trace # Print.
                say("Error with obtaining your access codes.", chan)
                return
        if command == "blockinfo":
                say(blockinfo(" ".join(line2[4:])), chan)
                return
        if command == "ipinfo":
                say(blockinfo(line2[4]), chan)
                say(getGeo(line2[4]),chan)
                return
        if command == "pull":
                if authtest(host, chan, 'dev'):
                        try:
                                import sys
                                sys.path.append("/home/deltaquad/")
                                os.system("git pull git@github.com:dqwiki/lisabot")
                                reply("Done.", chan, nick)
                        except:
                                reply("Error.", chan, nick)
                else:
                        reply(nodev, chan, nick)
                return
	if command == "restart":
		import thread, time
		if authtest(host, chan, 'dev'):
                        s.send("QUIT\r\n")
                        s.shutdown(socket.SHUT_RDWR)
                        time.sleep(2)
                        s2.send("QUIT\r\n")
                        s2.shutdown(socket.SHUT_RDWR)
			time.sleep(2)
			#os.system("exit")
			os.system("clear")
			os.system("nice -15 python main.py")
			os.abort()
			sys.exit("Trying to end process.")
			raise KeyboardInterrupt
		else:
			reply(nodev, chan, nick)
		return
	if command == "chan":
                reply(chan, chan, nick)
        if command == "request":
                #say(line2[4] + " to " + line2[5] +". Thank You!", chan)
                notice(nick, "Thank you for using the LisaBot paging system. Your message has been delievered over PM.")
                try:
                        notice(line2[4], "You have been requested to: " + line2[5] + " by " + nick + " for " + ' '.join(line2[6:]))
                except:
                        try:
                                notice(line2[4], "You have been requested by " + nick)
                        except:
                                notice(nick, "Your request format is invalid.")
                return
	if command == "myhost":
                reply(host, chan, nick)
                return
	if command == "sayhi":
                lisabot = "*waves* Hello, I am LisaBot. I run off of the Willow server on the Wikimedia Toolserver."
                reply(lisabot, chan, nick)
                return
	if command == "help":
                reply("http://bit.ly/lisahelp", chan, nick)
                return
        if command == "git":
                reply("https://github.com/dqwiki/lisabot/", chan, nick)
                return
	if command == "globalmsg":
		if authtest(host, chan, 'dev'):
			msg = "Global Notice for LisaBot: "		
                        msg = msg + ' '.join(line2[4:])
			notice("#wikipedia-en-abuse", msg)
			notice("#wikipedia-en-spi", msg)
			notice("##DeltaQuad", msg)
			notice("##LisaBot", msg)
			notice("##DeltaQuad-private", msg)
			notice("#techessentials", msg)
			notice("#techessentials-staff", msg)
			notice("#techessentials-security", msg)
		else:
			reply(nodev, chan, nick)
		return
	if command == "join":
		if authtest(host, chan, 'voice'):
			try:
				channel = line2[4]
			except Exception:
				channel = chan
			s.send("JOIN %s\r\n" % channel)
			reply('Done!', chan, nick)
		else:
			reply(novoice, chan, nick)
		return
	if command == "part":
		if authtest(host, chan, 'voice'):
			try:
				channel = line2[4]
			except Exception:
				channel = chan
			if not '#' in channel:
                                reason = channel
                                channel = chan
                        try:
                                reason = line2[5] + " (Requested by " +nick+")"
                                reply('Bye Bye!', chan, nick)
                                s.send("PART %s\r\n" % (channel,reason))
                        except:
                                reason = "Requested by " +nick+")"
                                reply('Bye Bye!', chan, nick)
                                s.send("PART %s :%s\r\n" % (channel,reason))
		else:
			reply(novoice, chan, nick)
		return
	if command == "quit":
		if authtest(host, chan, 'dev'):
				reply(nodev, chan, nick)
		else:
			try:
				s.send("QUIT :%s\r\n" % ' '.join(line2[4:]))
			except Exception:
				s.send("QUIT\r\n")
			import sys
			sys.exit(1)
		return
	if command == "msg":
		if authtest(host, chan, 'dev'):
			say(' '.join(line2[5:]), line2[4])
		else:
			reply(nodev, chan, nick)
		return
	if command == "me":
		if authtest(host, chan, 'dev'):
			s.send("PRIVMSG "+line2[4]+" ACTION "+ ' '.join(line2[5:]) )
		else:
			reply(nodev, chan, nick)
		return
	if command == "num" or command == "number" or command == "count" or command == "cases":
		try:
			params = string.lower(line2[4])
		except Exception:
			params = "spi"
		if params == "abuse":
                        invest = unicode(int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:Abuse_response_-_Waiting_for_Investigation&cmlimit=500").read()))))
                        o = unicode(int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:Abuse_response_-_Open&cmlimit=500").read()))))
                        reply("There are currently %s awaiting investigation and %s open investigations." % (invest, o), chan, nick)
                elif params == "spi":
                        try:
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
                                reply("SPI Status: CU Request - %s, CU Endorse - %s, CU in progress - %s, Checked/Open cases - %s, Archive - %s, Need admin - %s" % (cur, cuendorse, inprogress, waitclose, close, admin), chan, nick)
                                reply("And yes, this command has been fixed so that !num, !number, !count, and !cases will work.", chan, nick)
                        except:
                                print traceback.format_exc()
                                return
		return
	if command == "nick":
		if authtest(host, chan, 'dev'):
			try:
				new_nick = line2[4]
			except Exception:
				reply("Please specify a nick to change to.", chan, nick)
				return
			s.send("NICK %s\r\n" % new_nick)
		else:
			reply(nodev, chan, nick)
		return
	if command == "kick" or command == "ban" or command == "kickban" or command == "unban" or command == "quiet" or command == "unquiet":
                try:
                        user = line2[4]
                except Exception:
                        user = nick
                if (command == "kick" or command == "kickban" or command == "ban" or command == "quiet") and (user == "DeltaQuad" or "DQ|" in user or "Izhidez" in user):
                        if not host == 'wikipedia/DeltaQuad':
                                reply("Access denied, you are not DeltaQuad.", chan, nick)
                                return
                import time
                time.sleep(1)
                if authtest(host, chan, 'op') and (command == "kick" or command == "ban" or command == "kickban" or command == "unban"):
                        if "spi" in chan:say("op #wikipedia-en-spi LisaBot", "ChanServ")
                        try:
                                if command == "kick":
                                        s.send("KICK %s %s :%s\r\n" % (chan, line2[4], line2[4]))
                                if command == "ban":
                                        s.send("MODE %s +b %s\r\n" % (chan, line2[4]))
                                if command == "kickban":
                                        s.send("MODE 0%s +b %s\r\n" % (chan, line2[4]))
                                        s.send("KICK %s %s :%s\r\n" % (chan, line2[4], line2[4]))
                                if command == "unban":
                                        s.send("MODE %s -b %s\r\n" % (chan, line2[4]))
                                if command == "unquiet":
                                        s.send("MODE %s -q %s\r\n" % (chan, line2[4]))
                                if command == "quiet":
                                        s.send("MODE %s +q %s\r\n" % (chan, line2[4]))
                                time.sleep(1)
                                if "spi" in chan:say("deop #wikipedia-en-spi LisaBot", "ChanServ")
                        except:
                                if line2[4]:
                                        reply("I do not have sufficienct authorization.", chan, nick)
                                        print traceback.format_exc()
                                        return
                                else:
                                        reply("Please enter a user.", chan, nick)
                                        return
                elif authtest(host, chan, 'op') and (command == "quiet" or command == "unquiet"):
                        if "spi" in chan:say("op #wikipedia-en-spi LisaBot", "ChanServ")
                        try:
                                if command == "unquiet":
                                        s.send("MODE %s -q %s\r\n" % (chan, line2[4]))
                                if command == "quiet":
                                        s.send("MODE %s +q %s\r\n" % (chan, line2[4]))
                                time.sleep(1)
                                if "spi" in chan:say("deop #wikipedia-en-spi LisaBot", "ChanServ")
                        except:
                                reply("I do not have sufficienct authorization.", chan, nick)
                                print traceback.format_exc()
                                return
                else:
                        reply(noop, chan, nick)
                        return
        if command == "mode":
                import time
                if authtest(host, chan, 'op'):
                        try:
                                if line2[5]:
                                        if "spi" in chan:say("op #wikipedia-en-spi LisaBot", "ChanServ")
                                        if chan == "##DeltaQuadBot":
                                                say("op ##DeltaQuadBot LisaBot", "ChanServ")
                                                time.sleep(1)
                                        s.send("MODE %s %s %s\r\n" % (chan, line2[4], line2[5]))
                                        if chan == "##DeltaQuadBot":
                                                time.sleep(1)
                                                say("deop ##DeltaQuadBot LisaBot", "ChanServ")
                                        if "spi" in chan:say("deop #wikipedia-en-spi LisaBot", "ChanServ")
                        except:
                                if chan == "##DeltaQuadBot":say("op ##DeltaQuadBot LisaBot", "ChanServ")
                                if "spi" in chan:say("op #wikipedia-en-spi LisaBot", "ChanServ")
                                time.sleep(1)
                                s.send("MODE %s %s\r\n" % (chan, line2[4]))
                                time.sleep(1)
                                if "spi" in chan:say("deop #wikipedia-en-spi LisaBot", "ChanServ")
                                if chan == "##DeltaQuadBot":say("deop ##DeltaQuadBot LisaBot", "ChanServ")
                else:
                        reply(noop, chan, nick)
        if command == "stalk" or command == "unstalk" or command == "hide" or command == "unhide":
                reply("Due to new improvements to the RC system, these commands are currently disabled till they match the upgraded RC system. Please contact DeltaQuad to change what LisaBot stalks.", chan, nick)
                return
	if command == "startup":
                if authtest(host, chan, 'dev'):
                        channel = "#wikipedia-en-abuse-v"
                        s.send("JOIN %s\r\n" % channel)
			channel = "##DeltaQuad-private"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#wikipedia-en-unblock-dev"  
			s.send("JOIN %s\r\n" % channel)
			channel = "##DeltaQuad-RFA"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#everythingfoodanddrink"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#everythingfoodanddrink-mlpearc"  
			s.send("JOIN %s\r\n" % channel)
			channel = "##DeltaQuad-RC-admin"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#wikipedia-en-proxy"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#wikipedia-en-utrs"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#wikipedia-en-unblock-dev"
			s.send("JOIN %s\r\n" % channel)
			channel = "#wikipedia-en-accounts-admins"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#wikipedia-en-proxy"  
			s.send("JOIN %s\r\n" % channel)
			reply("Bot startup complete.", chan, nick)
		else:
			reply(nodev, chan, nick)
		return
	if command == "promote" or command == "demote" or command == "voice" or command == "devoice":
                try:
                        user = line2[4]
                except Exception:
                        user = nick
                if command == "promote":command="op"
                if command == "demote":command="deop"
                if (command == "deop" or command == "devoice") and (user == "DeltaQuad" or "DQ|" in user or "Izhidez" in user):
                        if not host == 'wikipedia/DeltaQuad':
                                reply("Access denied, you are not DeltaQuad.", chan, nick)
                                return
                if authtest(host, chan, 'op'):
                        try:
                                say("%s %s %s" % (command, chan, user), "ChanServ")
                        except:
                                reply(noop, chan, nick)
                        return
		elif authtest(host, chan, 'voice'):
                        if not command == "voice" and not command =="devoice":
                                reply(novoice, chan, nick)
                                return
			say("%s %s %s" % (command, chan, user), "ChanServ")
		else:
			reply(novoice, chan, nick)
		return
	if command == "trout":
                try:
                        user = line2[4] + ' '.join(line2[4:])
                except Exception:
                        reply("Hahahahahahahaha...", chan, nick)
                        return
                normal = unicodedata.normalize('NFKD', unicode(string.lower(user)))
                text = 'slaps %s around a bit with a large trout.' % user
                msg = '\x01ACTION %s\x01' % text
                say(msg, chan)
                return
	if command == "kill":
		reply("Who do you think I am? The Mafia?", chan, nick)
		return
	if command == "reminder":
                import time
		try:
			times = int(line2[4])
			content = ' '.join(line2[5:])
		except Exception:
			return reply("Please specify a time and a note in the following format: !remind <time> <note>.", chan, nick)
		reply("Set reminder for \"%s\" in %s seconds." % (content, times), chan, nick)
		time.sleep(times)
		reply(content, chan, nick)
		return
	if command == "langcode":
		try:
			lang = line2[4]
		except Exception:
			reply("Please specify an ISO code.", chan, nick)
			return
		data = urllib.urlopen("http://toolserver.org/~earwig/cgi-bin/swmt.py?action=iso").read()
		data = string.split(data, "\n")
		result = False
		for datum in data:
			if datum.startswith(lang):
				result = re.findall(".*? (.*)", datum)[0]
				break
		if result:
			reply(result, chan, nick)
			return
		reply("Not found.", chan, nick)
		return
	if command == "geolocate":
                try:
                        say(getGeo(line2[4]), chan)
                except:
                        say("Try a valid IP address.", chan)
	if command == "perms" or command == "permission" or command == "permissions":
                if not authtest(host, chan, 'secure'):return reply(nosecure, chan, nick)
                ####Format Check
                options=["read","list","del","remove","add","change","modify"]
                level=["dev","secure","op","voice","blocked"]
                ractivity = line2[4]
                rscope = line2[5]
                rcloak = line2[6]
                rlevel = line2[7]
                if rcloak not in options:return reply("You did not specify an action in the first argument, your options are: " + " ".join(options), chan, nick)
                if not rscope == "local" or not rscope == "global" :return reply("You did not specify the scope (global vs. local).", chan, nick)
                if "@" not in rcloak or "/" not in rcloak:return reply("You did not specify a cloak in the second argument.", chan, nick)
                if not ractivity in ["read","list","del","remove"]:
                        if rlevel not in options:return reply("You did not specify a permission level in the third argument, your options are: " + " ".join(level), chan, nick)
                        if rlevel == 'blocked' and not authtest(host, chan, 'dev'):return reply(nodev, chan, nick)
                ####Run by action request
		if ractivity == "read" or ractivity == "list":
                        if rscope == "local":
                                try:f = open('perms-'+chan+'.txt', 'r')
                                except IOError:return reply("Error in accessing permissions", chan, nick)
                        if not rscope == "local":
                                try:f = open('perms-global.txt', 'r')
                                except IOError:return reply("Error in accessing permissions", chan, nick)
                        text = f.read()
                        f.close()
                        if authtest(host, chan, 'dev'):return notice(nick, text)
                        for pline in text:
                                spline=pline.split(',')
                                if spline[0] == rcloak:
                                        return reply(pline, chan, nick)
                ####Either way, actions below will need files opened the same way
                if rscope == "local":
                        try:f = open('perms-'+chan+'.txt', 'r+')
                        except IOError:return reply("Error in accessing permissions", chan, nick)
                if not rscope == "local":
                        try:f = open('perms-global.txt', 'r+')
                        except IOError:return reply("Error in accessing permissions", chan, nick)
                text = f.read()
                if ractivity == "add":
                        if rcloak not in text:text = text + "\n"+rcloak+","+rlevel
                        else:return reply("Permissions are already on file, please modify them instead of trying to add a new entry", chan, nick)
                done = False
                for pline in text:
                        spline=pline.split(',')
                        if (ractivity == "del" or ractivity == "remove") and spline[0] == rcloak:
                                text.replace(pline,"")
                                done=True
                                break
                        elif ractivity=="change" or ractivity == "modify":
                                if rcloak in text:
                                        text.pop(pline)
                                        text = text + "\n"+rcloak+","+rlevel
                                        done = True
                                        break
                if not done:
                        f.close()
                        return reply("Permissions are not on file, please add them first.", chan, nick)
                text = text.replace("\n\n","\n")
                f.write(text)
                f.close()
                return
def getGeo(ip):#,loc):
        # Copyright (c) 2010, Westly Ward
        # All rights reserved.
        #
        # Redistribution and use in source and binary forms, with or without
        # modification, are permitted provided that the following conditions are met:
        # * Redistributions of source code must retain the above copyright
        # notice, this list of conditions and the following disclaimer.
        # * Redistributions in binary form must reproduce the above copyright
        # notice, this list of conditions and the following disclaimer in the
        # documentation and/or other materials provided with the distribution.
        # * Neither the name of the pyipinfodb nor the
        # names of its contributors may be used to endorse or promote products
        # derived from this software without specific prior written permission.
        #
        # THIS SOFTWARE IS PROVIDED BY Westly Ward/DeltaQuad ''AS IS'' AND ANY
        # EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
        # WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
        # DISCLAIMED. IN NO EVENT SHALL Westly Ward BE LIABLE FOR ANY
        # DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
        # (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
        # LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
        # ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
        # (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
        # SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
        import urllib,urllib2,json
        """Same as GetCity and GetCountry, but a baseurl is required. This is for if you want to use a different server that uses the the php scripts on ipinfodb.com."""
        passdict = {"output":"json", "key":KEY, "timezone":"true", "ip":ip}
        urldata = urllib.urlencode(passdict)
        baseurl = "http://api.ipinfodb.com/v2/ip_query.php"
        url = str(baseurl) + "?" + str(urldata)
        urlobj = urllib2.urlopen(url)
        data = urlobj.read()
        urlobj.close()
        datadict = json.loads(data)
        info = datadict
        #END
        if not info["Status"] == "OK":
                return "Try a valid IP address"
        #if loc:
                #return "Long: " + str(info["Longitude"]) + " Lat: " + str(info["Latitude"]) + "."
        if str(info["City"]) == "":
               info["City"] == "Unknown"
        if str(info["RegionName"]) == "":
               info["City"] == "Unknown"
        return "Estimated Location for "+str(info['Ip'])+" : " + str(info["City"]) + ", "+ str(info["RegionName"]) + ", "+ str(info["CountryName"]) + ". Timezone: "+ str(info["TimezoneName"])

def blockinfo(IP):
        ###Needs to be simplified with JSON
        import urllib,urllib2,json,re
        test = re.search("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",IP)
        if test == None:#user
            passdict = {"action":"query", "list":"blocks", "bkprop":"id|user|by|timestamp|expiry|reason|range|flags", "bklimit":"1","bkusers":IP}
        else:#ip
            passdict = {"action":"query", "list":"blocks", "bkprop":"id|user|by|timestamp|expiry|reason|range|flags", "bklimit":"1","bkip":IP}
        urldata = urllib.urlencode(passdict)
        baseurl = "http://en.wikipedia.org/w/api.php"
        url = str(baseurl) + "?" + str(urldata)
        urlobj = urllib2.urlopen(url)
        json = urlobj.read()
        urlobj.close()
        try:json = json.split("<span style=\"color:blue;\">&lt;blocks&gt;</span>")[1]
        except:return "User is not blocked."
        json = json.split("<span style=\"color:blue;\">&lt;/blocks&gt;</span>")[0]
        json = json.split("<span style=\"color:blue;\">&lt;")[1]
        json = json.replace("&quot;","\"")
        bid=json.split("block id=\"")[1]
        bid=bid.split("\"")[0]
        gen="Block " + str(bid)
        bid=json.split("user=\"")[1]
        bid=bid.split("\"")[0]
        gen=gen+" targeting " + str(bid)
        bid=json.split("by=\"")[1]
        bid=bid.split("\"")[0]
        gen=gen+" was blocked by " + str(bid)
        bid=json.split("timestamp=\"")[1]
        bid=bid.split("\"")[0]
        gen=gen+" @" + str(bid)
        bid=json.split("expiry=\"")[1]
        bid=bid.split("\"")[0]
        gen=gen+" and expires at " + str(bid)
        bid=json.split("reason=\"")[1]
        bid=bid.split("\"")[0]
        gen=gen+" because \"" + str(bid) + "\" ("
        gen = gen.replace("&amp;lt;","<")
        gen = gen.replace("&amp;gt;",">")
        if "nocreate" in json:
            gen = gen + "Account Creation Blocked, "
        if "anononly" in json:
            gen = gen + "Anonomous Users Only, "
        else:
            gen = gen + "Hardblocked, "
        if not "allowusertalk" in json:
            gen = gen + "User Talk Page REVOKED)"
        else:
            gen = gen + "User Talk Page allowed)"
        return gen
