##LisaBot - IRC Bot
##Copyright (C) 2011 DeltaQuad
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

## MySQL constants for access commands
op=2
voice=3
ban=4
kick=5
globalmsg=6
startup=7
quiet=8
nick=9
mode=10
trout=11
permission=12
restart=13
joinpart=14
blocked=15

def authdb(host, chan):
        import MySQLdb, traceback
        db = MySQLdb.connect(db="u_deltaquad_rights", host="sql", read_default_file="/home/deltaquad/.my.cnf")
        specify = host
        if " " in specify: specify = string.split(specify, " ")[0]
        if not specify or "\"" in specify:
                reply("Please include the name of the entry you would like to read after the command, e.g. !notes read earwig", chan, nick)
                print "error"
        if '@' not in specify:specify = '@' + specify
        try:
                db.query("SELECT * FROM accessnew WHERE cloak = \"%s\" AND channel = \"%s\";" %(specify,chan))
                r = db.use_result()
                try:
                        data = r.fetch_row(0)[0]
                        print data[5]
                        auth = data
                except:auth = ['@none', '@global', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                db.query("SELECT * FROM accessnew WHERE cloak = \"%s\" AND channel = \"@global\";" %specify)
                rglobal = db.use_result()
                try:
                        authglobal = rglobal.fetch_row(0)[0]
                        print authglobal[5]
                except:authglobal = ['@none', '@global', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                count = 0
                authfinal = []
                authfinal.insert(-1, '@none')
                authfinal.insert(1, '@global')
                for entry in authglobal:
                        count = count + 1
                        try:float(entry)
                        except ValueError:continue
                        if entry == 0:authfinal.insert(count-1, auth[count-1]) 
                        else:
                                try:
                                        authfinal[count-1] = authglobal[count-1]
                                except:
                                        authfinal.insert(count-1, authglobal[count-1]) 
                #print authfinal
                return authfinal
        except:
                trace = traceback.format_exc() # Traceback.
                print trace # Print.
                return

def authtest(host, chan):
        if not "@" in host:host= "@" + host
	if host == OWNER:
                print "owner"
		return "owner"
        elif host == BOT:
                print "bot"
		return "bot"
	else:
                print "AuthDB"
                return authdb(host, chan)
	return False
def get_commandList():
	return {'quiet': 'quiet',
	'welcome': 'welcome',
	'greet': 'welcome',
	'auth': 'auth',
	'access': 'access',
        'link':'link',
	'join': 'join',
	'leave': 'part',
	'restart': 'restart',
	'quit': 'quit',
	'die': 'quit',
	'suicide': 'quit',
	'msg': 'msg',
	'me': 'me',
	'calc': 'calc',
	'dice': 'dice',
	'time': 'time',
	'beats': 'beats',
	'dict': 'dictionary',
	'dictionary': 'dictionary',
	'ety': 'etymology',
	'etymology': 'etymology',
	'lang': 'langcode',
	'langcode': 'langcode',
	'num': 'number',
	'number': 'number',
	'count': 'number',
	'nick': 'nick',
	'promote': 'promote',
	'demote': 'demote',
	'voice': 'voice',
	'devoice': 'devoice',
	'pend': 'pending',
	'pending': 'pending',
	'praise': 'praise',
	'trout': 'trout',
        'page': 'request',
        'request': 'request',
	'kill': 'kill',
	'destroy': 'kill',
	'murder': 'kill',
	'commands': 'commands',
        'clear': 'clear',
	'help': 'help',
	'myaccess': 'myaccess',
	'doc': 'help',
	'documentation': 'help',
	'remind': 'reminder',
	'reminder': 'reminder',
        'ban': 'ban',
        'kick': 'kick',
        'unban': 'unban',
        'sayhi': 'sayhi',
        'new': 'new',
        'version': 'version',
        'support': 'support',
        'globalmsg': 'globalmsg',
	}

def main(command, line, line2, nick, chan, host, auth, notice, say, reply, s, s2, lastlink):
	try:
		parse(command, line, line2, nick, chan, host, auth, notice, say, reply, s, s2, lastlink)
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
def quiet():
        import MySQLdb
	db = MySQLdb.connect(db="u_deltaquad_rights", host="sql", read_default_file="/home/deltaquad/.my.cnf")
        db.query("SELECT * FROM config WHERE param = \"quiet\";")
        r = db.use_result()
        data = r.fetch_row(0)
        result=data[0][1]
        if result == "true" or result == "TRUE" or result == "True":
                return True
        else:
                return False
def parse(command, line, line2, nick, chan, host, auth, notice, say, reply, s, s2, lastlink):
	actionlevel = authtest(host, chan)
	print actionlevel
	try:
                if actionlevel[blocked] == 1:return
        except:
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
                if actionlevel[restart] == 1:
                        try:
                                import sys
                                sys.path.append("/home/deltaquad/")
                                os.system("git pull git@github.com:dqwiki/lisabot")
                                reply("Done.", chan, nick)
                        except:
                                reply("Error.", chan, nick)
                else:
                        reply("Access Denied, you need the +r (restart flag) to use this action.", chan, nick)
                return
	if command == "restart":
		import thread, time
		if actionlevel[restart] == 1:
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
			raise SystemExit
		else:
			reply("Access Denied, you need the +r (restart flag) to use this action.", chan, nick)
		return
	if command == "chan":
                reply(chan, chan, nick)
        if command == "request" or command == "page":
                if actionlevel[trout]==0:
                        reply("Access Denied, you need the +t (trout flag) to use this action.", chan, nick)
                        return
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
                lisabot = "*waves* Hello I am LisaBot. I run off of the Willow server on the Wikimedia Toolserver."
                reply(lisabot, chan, nick)
                return
        if command == "support":
                reply("http://support.lisabot.org/", chan, nick)
                return
        if command == "project":
                reply("http://lisabot.org/", chan, nick)
                return
        if command == "version":
                reply("Version = 1.11.01 Beta", chan, nick)
                return
        if command == "new":
                reply("Version 1.11.01 Beta", chan, nick)
                reply("Added !ops", chan, nick)
                reply("Fixed links hopefully", chan, nick)
                reply("Minor fixes", chan, nick)
                reply("Release on 08/05/2011", chan, nick)
                return
        if command == "dev" or command == "devs" or command == "developers":
                reply("DeltaQuad - Project Manager/Owner", chan, nick)
                reply("Pilif12p - Lead Programmer", chan, nick)
                reply("JoeGazz84 - Security Manager", chan, nick)
                return
	if command == "help" or command == "commands":
                reply("http://lisabot.org/index.php/commands", chan, nick)
                return
        if command == "bugs" or command == "bug":
                reply("https://github.com/dqwiki/lisabot/issues", chan, nick)
                return
        if command == "git" or command == "github":
                reply("https://github.com/dqwiki/lisabot/", chan, nick)
                return
       	if command == "access":
		reply("http://lisabot.org/index.php/access-levels", chan, nick)
		return
	if command == "requestvoice":
                if "rfa" in chan:reply("\x0312"+nick + " \x0312has requested a voice in "+chan+". \x0301\x02Ping: DeltaQuad, Thehelpfulone, Gfoley4, Mlpearc, Courcelles.", "##DeltaQuad", nick)
                if "rfa" in chan:reply("\x0312"+nick + " \x0312has requested a voice in "+chan+". \x0301\x02Ping: DeltaQuad, Thehelpfulone, Gfoley4, Mlpearc, Courcelles.", "##DeltaQuad-rfa", nick)
                else:reply("\x0312"+nick + " \x0312has requested a voice in "+chan+". \x0301\x02Ping: DeltaQuad.", "##DeltaQuad", nick)
                return
	if command == "ops":
                if "rfa" in chan:
                        reply("\x0312"+nick + " \x0304has requested operator attention in "+chan+". \x0301\x02Ping: DeltaQuad, Thehelpfulone, Gfoley4, Mlpearc, Courcelles.", "##DeltaQuad", nick)
                        reply("\x0312"+nick + " \x0304has requested operator attention in "+chan+". \x0301\x02Ping: DeltaQuad, Thehelpfulone, Gfoley4, Mlpearc, Courcelles.", "##DeltaQuad-rfa", nick)
                elif "DeltaQuad" in chan:reply("\x0312"+nick + " \x0304has requested operator attention in "+chan+". \x0301\x02Ping: DeltaQuad, AFK, JoeGazz84, Pilif12p, Thehelpfulone, Gfoley4.", "##DeltaQuad", nick)
                elif "techessentials" in chan:reply("\x0312"+nick + " \x0304has requested operator attention in "+chan+". \x0301\x02Ping: DeltaQuad, AFK, JoeGazz84, Pilif12p, Netalarm.", "#techessentials", nick)
                elif "spi" in chan:reply("\x0312"+nick + " \x0304has requested operator attention. \x0301\x02Ping: DeltaQuad, !clerk, MuZemike, Courcelles, Dmcdevit, Tnxman307, Avi|work, FT2, Shirik, SpitfireWP, Timotheus_Canens.", "#wikipedia-en-spi", nick)
                elif "afc" in chan:reply("\x0312"+nick + " \x0304has requested operator attention. \x0301\x02Ping: Earwig", "#wikipedia-en-afc", nick)
                elif "abuse" in chan:reply("\x0312"+nick + " \x0304has requested operator attention. \x0301\x02Ping: Netalarm, DeltaQuad", "#wikipedia-en-afc", nick)
                else:reply("\x0312"+nick + " \x0304has requested operator attention in "+chan+". \x0301\x02Ping: DeltaQuad, AFK, JoeGazz84, Pilif12p, Thehelpfulone, Gfoley4.", "##DeltaQuad", nick)
                return
	if command == "globalmsg":
		if actionlevel[globalmsg] == 1:
			msg = "Global Notice for LisaBot: "		
                        msg = msg + ' '.join(line2[4:])
			notice("#wikipedia-en-abuse", msg)
			notice("#wikipedia-en-abuse-v", msg)
			notice("#wikipedia-en-spi", msg)
			notice("##DeltaQuad", msg)
			notice("##LisaBot", msg)
			notice("##DeltaQuad-private", msg)
			notice("#techessentials", msg)
			notice("#techessentials-staff", msg)
			notice("#techessentials-security", msg)
			notice("#techessentials-techops", msg)
		else:
			reply("Access Denied, you need the +g (global flag) to use this action.", chan, nick)
		return
	if command == "myaccess":
                try:
                        temp5 = authtest((line2[4:])[0], chan, "soft")
                        reply('Access Codes: %s' % temp5, chan, nick)
                except:
                        temp5 = authtest(host, chan, "soft")
                        reply('Access Codes: %s' % temp5, chan, nick)
                return
	if command == "join":
		if actionlevel[joinpart] == 1:
			try:
				channel = line2[4]
			except Exception:
				channel = chan
			s.send("JOIN %s\r\n" % channel)
			reply('Done!', chan, nick)
		else:
			reply("Access Denied, you need the +j (join/part flag) to use this action.", chan, nick)
		return
	if command == "part":
		if actionlevel[joinpart] == 1:
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
			reply("Access Denied, you need the +j (join/part flag) to use this action.", chan, nick)
		return
	if command == "quit" or command == "die" or command == "suicide":
		if actionlevel[startup] == 0:
				reply("Access Denied, you need the +p (power flag) to use this action." % OWNER, chan, nick)
		else:
			try:
				s.send("QUIT :%s\r\n" % ' '.join(line2[4:]))
			except Exception:
				s.send("QUIT\r\n")
			import sys
			sys.exit(1)
		return
	if command == "msg":
		if actionlevel[startup] == 1:
			say(' '.join(line2[5:]), line2[4])
		else:
			reply("Access Denied, you need the +s (talk as bot flag) to use this action.", chan, nick)
		return
	if command == "time":
		u = urllib.urlopen('http://tycho.usno.navy.mil/cgi-bin/timer.pl')
		info = u.info()
		u.close()
		say('"' + info['Date'] + '" - tycho.usno.navy.mil', chan)
		return
	if command == "beats":
		beats = ((time.time() + 3600) % 86400) / 86.4
		beats = int(math.floor(beats))
		say('@%03i' % beats, chan)
		return
	if command == "dict" or command == "dictionary":
		def trim(thing): 
			if thing.endswith('&nbsp;'): 
				thing = thing[:-6]
			return thing.strip(' :.')
		r_li = re.compile(r'(?ims)<li>.*?</li>')
		r_tag = re.compile(r'<[^>]+>')
		r_parens = re.compile(r'(?<=\()(?:[^()]+|\([^)]+\))*(?=\))')
		r_word = re.compile(r'^[A-Za-z0-9\' -]+$')
		uri = 'http://encarta.msn.com/dictionary_/%s.html'
		r_info = re.compile(r'(?:ResultBody"><br /><br />(.*?)&nbsp;)|(?:<b>(.*?)</b>)')
		try:
			word = line2[4]
		except Exception:
			reply("Please enter a word.", chan, nick)
			return
		word = urllib.quote(word.encode('utf-8'))
		bytes = web.get(uri % word)
		results = {}
		wordkind = None
		for kind, sense in r_info.findall(bytes): 
			kind, sense = trim(kind), trim(sense)
			if kind: wordkind = kind
			elif sense: 
				results.setdefault(wordkind, []).append(sense)
		result = word.encode('utf-8') + ' - '
		for key in sorted(results.keys()): 
			if results[key]: 
				result += (key or '') + ' 1. ' + results[key][0]
				if len(results[key]) > 1: 
					result += ', 2. ' + results[key][1]
				result += '; '
		result = result.rstrip('; ')
		if result.endswith('-') and (len(result) < 30): 
			reply('Sorry, no definition found.', chan, nick)
		else: say(result, chan)
		return
	if command == "ety" or command == "etymology":
		etyuri = 'http://etymonline.com/?term=%s'
		etysearch = 'http://etymonline.com/?search=%s'
		r_definition = re.compile(r'(?ims)<dd[^>]*>.*?</dd>')
		r_tag = re.compile(r'<(?!!)[^>]+>')
		r_whitespace = re.compile(r'[\t\r\n ]+')
		abbrs = [
			'cf', 'lit', 'etc', 'Ger', 'Du', 'Skt', 'Rus', 'Eng', 'Amer.Eng', 'Sp', 
			'Fr', 'N', 'E', 'S', 'W', 'L', 'Gen', 'J.C', 'dial', 'Gk', 
			'19c', '18c', '17c', '16c', 'St', 'Capt', 'obs', 'Jan', 'Feb', 'Mar', 
			'Apr', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec', 'c', 'tr', 'e', 'g'
		]
		t_sentence = r'^.*?(?<!%s)(?:\.(?= [A-Z0-9]|\Z)|\Z)'
		r_sentence = re.compile(t_sentence % ')(?<!'.join(abbrs))
		def unescape(s): 
			s = s.replace('&gt;', '>')
			s = s.replace('&lt;', '<')
			s = s.replace('&amp;', '&')
			return s
		def text(html): 
			html = r_tag.sub('', html)
			html = r_whitespace.sub(' ', html)
			return unescape(html).strip()
		try:
			word = line2[4]
		except Exception:
			reply("Please enter a word.", chan, nick)
			return
		def ety(word):
			if len(word) > 25: 
				raise ValueError("Word too long: %s[...]" % word[:10])
			word = {'axe': 'ax/axe'}.get(word, word)
			bytes = web.get(etyuri % word)
			definitions = r_definition.findall(bytes)
			if not definitions: 
				return None
			defn = text(definitions[0])
			m = r_sentence.match(defn)
			if not m: 
				return None
			sentence = m.group(0)
			try: 
				sentence = unicode(sentence, 'iso-8859-1')
				sentence = sentence.encode('utf-8')
			except: pass
			maxlength = 275
			if len(sentence) > maxlength: 
				sentence = sentence[:maxlength]
				words = sentence[:-5].split(' ')
				words.pop()
				sentence = ' '.join(words) + ' [...]'
			sentence = '"' + sentence.replace('"', "'") + '"'
			return sentence + ' - ' + (etyuri % word)
		try:
			result = ety(word.encode('utf-8'))
		except IOError: 
			msg = "Can't connect to etymonline.com (%s)" % (etyuri % word)
			reply(msg, chan, nick)
			return
		except AttributeError: 
			result = None
		if result is not None: 
			reply(result, chan, nick)
		else: 
			uri = etysearch % word
			msg = 'Can\'t find the etymology for "%s". Try %s' % (word, uri)
			reply(msg, chan, nick)
		return
	if command == "num" or command == "number" or command == "count":
		try:
			params = string.lower(line2[4])
		except Exception:
			params = False
			print traceback.format_exc()
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
                                waitclose = int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:SPI_Cases_needing_a_clerk&cmlimit=500").read())))
                                time.sleep(.25)
                                close = int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:SPI_cases_pending_close&cmlimit=500").read())))
                                time.sleep(.25)
                                admin = int(len(re.findall("title=", urllib.urlopen("http://en.wikipedia.org/w/api.php?action=query&list=categorymembers&cmtitle=Category:SPI_requests_needing_an_Administrator&cmlimit=500").read())))
                                time.sleep(.25)
                                print "Send Msg"
                                reply("SPI Status: CU Request - %s, CU Endorse - %s, CU in progress - %s, Checked/Actioned - %s, Archive - %s, Need admin - %s" % (cur, cuendorse, inprogress, waitclose, close, admin), chan, nick)
                        except:
                                print traceback.format_exc()
                                return
		return
	if command == "nick":
		if actionlevel[nick] == 1:
			try:
				new_nick = line2[4]
			except Exception:
				reply("Please specify a nick to change to.", chan, nick)
				return
			s.send("NICK %s\r\n" % new_nick)
		else:
			reply("Access Denied, you need the +n (nick flag) to use this action.", chan, nick)
		return
	if command == "kick" or command == "ban" or command == "kickban" or command == "unban" or command == "quiet" or command == "unquiet":
                if actionlevel[ban] == 1 and (command == "kick" or command == "ban" or command == "kickban" or command == "unban"):      
                        try:
                                if command == "kick":
                                        s.send("KICK %s %s :%s\r\n" % (chan, line2[4], line2[4]))
                                if command == "ban":
                                        s.send("MODE %s +b %s\r\n" % (chan, line2[4]))
                                if command == "kickban":
                                        s.send("MODE %s +b %s\r\n" % (chan, line2[4]))
                                        s.send("KICK %s %s :%s\r\n" % (chan, line2[4], line2[4]))
                                if command == "unban":
                                        s.send("MODE %s -b %s\r\n" % (chan, line2[4]))
                                if command == "unquiet":
                                        s.send("MODE %s -q %s\r\n" % (chan, line2[4]))
                                if command == "quiet":
                                        s.send("MODE %s +q %s\r\n" % (chan, line2[4]))
                        except:
                                if line2[4]:
                                        reply("I do not have sufficienct authorization.", chan, nick)
                                        print traceback.format_exc()
                                        return
                                else:
                                        reply("Please enter a user.", chan, nick)
                                        return
                elif actionlevel[quiet] == 1 and (command == "quiet" or command == "unquiet"):      
                        try:
                                if command == "unquiet":
                                        s.send("MODE %s -q %s\r\n" % (chan, line2[4]))
                                if command == "quiet":
                                        s.send("MODE %s +q %s\r\n" % (chan, line2[4]))
                        except:
                                reply("I do not have sufficienct authorization.", chan, nick)
                                print traceback.format_exc()
                                return
                else:
                        reply("Access Denied, you need the +b/q (ban/quiet flag) to use this action.", chan, nick)
                        return
        if command == "mode":
                import time
                if actionlevel[mode] == 1:
                        try:
                                if line2[5]:
                                        if chan == "##DeltaQuadBot":
                                                say("op ##DeltaQuadBot LisaBot", "ChanServ")
                                                time.sleep(1)
                                        s.send("MODE %s %s %s\r\n" % (chan, line2[4], line2[5]))
                                        if chan == "##DeltaQuadBot":
                                                time.sleep(1)
                                                say("deop ##DeltaQuadBot LisaBot", "ChanServ")
                        except:
                                if chan == "##DeltaQuadBot":say("op ##DeltaQuadBot LisaBot", "ChanServ")
                                time.sleep(1)
                                s.send("MODE %s %s\r\n" % (chan, line2[4]))
                                time.sleep(1)
                                if chan == "##DeltaQuadBot":say("deop ##DeltaQuadBot LisaBot", "ChanServ")
                else:
                        reply("Access Denied, you need the +m (mode flag) to use this action.", chan, nick)
	if command == "startup":
                if actionlevel[startup] == 1:
                        channel = "#wikipedia-en-abuse-v"
                        s.send("JOIN %s\r\n" % channel)
			channel = "##DeltaQuad-private"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#techessentials"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#techessentials-staff"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#techessentials-security"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#techessentials-techops"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#techessentials-mlpearc"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#techessentials-deltaquad"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#techessentials-design"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#techessentials-apple"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#testwiki"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#techessentials-managers"  
			s.send("JOIN %s\r\n" % channel)
			channel = "##DeltaQuad-RFA"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#everythingfoodanddrink"  
			s.send("JOIN %s\r\n" % channel)
			channel = "##DeltaQuad-RC-admin"  
			s.send("JOIN %s\r\n" % channel)
			channel = "#wikipedia-en-proxy"  
			s.send("JOIN %s\r\n" % channel)
			reply("Bot startup complete.", chan, nick)
		else:
			reply("Access Denied, you need the +s (startup flag) to use this action.", chan, nick)
		return
	if command == "promote" or command == "demote" or command == "voice" or command == "devoice":
                if command == "promote":command="op"
                if command == "demote":command="deop"
                if actionlevel[op] == 1:
                        try:
                                try:
                                        user = line2[4]
                                except Exception:
                                        user = nick
                                say("%s %s %s" % (command, chan, user), "ChanServ")
                        except:
                                reply("Access Denied, you need the +o (op flag) to use this action.", chan, nick)
                        return
		elif actionlevel[voice] == 1:
                        if command == "op":return
                        try:
				user = line2[4]
			except Exception:
				user = nick
			say("%s %s %s" % (command, chan, user), "ChanServ")
		else:
			reply("Access Denied, you need the +v (voice flag) to use this action.", chan, nick)
		return
	if command == "trout":
                if actionlevel[trout] == 1:
                        try:
                                user = line2[4]
                                user = ' '.join(line2[4:])
                        except Exception:
                                reply("Hahahahahahahaha...", chan, nick)
                                return
                        normal = unicodedata.normalize('NFKD', unicode(string.lower(user)))
                        if "itself" in normal:
                                reply("I'm not that stupid ;)", chan, nick)
                                return
                        elif "Lisa" in normal or "LisaBot" in normal or "lisa" in normal:
                                reply("I'm not that stupid ;)", chan, nick)
                        elif "deltaquad" not in normal and "DeltaQuad" not in normal and "DQ" not in normal and "dq" not in normal and "FAdmArcher" not in normal and "FADMArcher" not in normal and "fadmarcher" not in normal:
                                text = 'slaps %s around a bit with a large trout.' % user
                                msg = '\x01ACTION %s\x01' % text
                                say(msg, chan)
                        else:
                                reply("I refuse to hurt anything with \"DeltaQuad\" in its name :P", chan, nick)
                        return
                else:
                        reply("Access Denied, you need the +t (trout flag) to use this action.", chan, nick)
                        
	if command == "kill" or command == "destroy" or command == "murder":
		reply("Who do you think I am? The Mafia?", chan, nick)
		return
	if command == "fish":
                if actionlevel[trout] == 1:
                        try:
                                user = line2[4]
                                fish = ' '.join(line2[5:])
                        except Exception:
                                reply("Hahahahahahahaha...", chan, nick)
                                return
                        normal = unicodedata.normalize('NFKD', unicode(string.lower(user)))
                        if "itself" in normal:
                                reply("I'm not that stupid ;)", chan, nick)
                                return
                        elif "lisabot" in normal or "LisaBot" in normal or "Lisa" in normal:
                                reply("I'm not that stupid ;)", chan, nick)
                        elif "deltaquad" not in normal and "DeltaQuad" not in normal:
                                text = 'slaps %s around a bit with a %s.' % (user, fish)
                                msg = '\x01ACTION %s\x01' % text
                                say(msg, chan)
                        else:
                                reply("I refuse to hurt anything with \"DeltaQuad\" in its name :P", chan, nick)
                        return
                else:
                        reply("Access Denied, you need the +t (trout flag) to use this action.", chan, nick)
	if command == "remind" or command == "reminder":
                import time
		try:
			times = int(line2[4])
			content = ' '.join(line2[5:])
		except Exception:
			reply("Please specify a time and a note in the following format: !remind <time> <note>.", chan, nick)
			return
		reply("Set reminder for \"%s\" in %s seconds." % (content, times), chan, nick)
		time.sleep(times)
		reply(content, chan, nick)
		return
	if command == "langcode" or command == "lang" or command == "language":
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
                        say(getGeo(line2[4]), chan)#, False)
                        #say(getGeo(line2[4]), chan)#, True)
                except:
                        say("Try a valid IP address.", chan)
	if command == "sql" or command == "perms":
                if not actionlevel[permission] == 1:
                        reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                        return
                try:
			action = line2[4]
		except BaseException:
			reply("What do you want me to do?", chan, nick)
			return
                import MySQLdb
		db = MySQLdb.connect(db="u_deltaquad_rights", host="sql", read_default_file="/home/deltaquad/.my.cnf")
		reqchan = str(line2[5])
		cloak = str(line2[6])
		if action == "read":
                        if " " in cloak: cloak = string.split(cloak, " ")[0]
                        if not cloak or "\"" in cloak:
                                reply("Please include the name of the entry you would like to read after the command.", chan, nick)
                                return
                        try:
                                if line2[5] == "@global":
                                        channew = "@global"
                                        db.query("SELECT * FROM accessnew WHERE cloak = \"%s\" AND channel = \"@global\";" % (cloak,reqchan))
                                else:
                                        channew = chan
                                        db.query("SELECT * FROM accessnew WHERE cloak = \"%s\ AND channel = \"%s\";" % (cloak,reqchan))
                                r = db.use_result()
                                data = r.fetch_row(0)
                                cloak = data[0][0]
                                channel=data[0][1]
                                #s added to all commands because without 's' is already defined
                                ops=data[0][2]
                                voices=data[0][3]
                                bans=data[0][4]
                                kicks=data[0][5]
                                globalmsgs=data[0][6]
                                startups=data[0][7]
                                quiets=data[0][8]
                                nicks=data[0][9]
                                modes=data[0][10]
                                trouts=data[0][11]
                                permissions=data[0][12]
                                restarts=data[0][13]
                                joinparts=data[0][14]
                                blockeds=data[0][15]
                                notice(nick, "Entry \"\x02%s\x0F\": Cloak: %s Channel: %s Ops: %s Voice: %s Globalmsg/Startup: %s Nick: %s Ban: %s Quiet: %s Mode: %s Trout: %s Permission: %s Restart: %s Join/part: %s Blocked: %s" % (specify, channew, ops, voices, bans, kicks, globalmsgs, startups, quiets, nicks, modes, trouts, permissions, restarts, joinparts, blockeds), chan)
                        except Exception:
                                print traceback.format_exc()
                                reply("There is no cloak titled \"\x02%s\x0F\"." % cloak, chan, nick)
                        return
                reply("All permission modifications are disabled at this time.", chan, nick)
                return
        """        elif action == "del":
                        if " " in specify:specify = string.split(specify, " ")[0]
                        if not specify or "\"" in specify:
                                reply("Invalid command", chan, nick)
                                return
                        try:
                                db.query("DELETE * FROM access WHERE cloak = \"%s\";" % specify)
                                db.commit()
                        except Exception:
                                reply("Error", chan, nick)
                elif action == "modify":
                        field = string.lower(' '.join(line2[6:]))
                        field = field.split(' ')[0]
                        level = string.lower(' '.join(line2[7:]))
                        if " " in specify: specify = string.split(specify, " ")[0]
                        if not specify or "\"" in specify:
                                reply("Invalid command", chan, nick)
                                return
                        try:
                                print level
                                print specify
                                print field
                                if field == "spi":
                                        if not "f" in authtest(host, "#wikipedia-en-spi", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("UPDATE access SET spi=\'%s\' WHERE cloak=\'%s\';" % (level, specify))
                                        db.commit()
                                        reply("Done!", chan, nick)
                                        return
                                elif field == "abuse":
                                        if not "f" in authtest(host, "#wikipedia-en-abuse", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("UPDATE access SET abuse=\'%s\' WHERE cloak=\"%s\";" % (level, specify))
                                        db.commit()
                                        reply("Done!", chan, nick)
                                        return
                                elif field == "dq" or field == "deltaquad":
                                        if not "f" in authtest(host, "##DeltaQuad", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("UPDATE access SET dq=\'%s\' WHERE cloak=\'%s\';" % (level, specify))
                                        db.commit()
                                        reply("Done!", chan, nick)
                                        return
                                elif field == "te":
                                        if not "f" in authtest(host, "#techessentials", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("UPDATE access SET te=\'%s\' WHERE cloak=\'%s\';" % (level, specify))
                                        db.commit()
                                        reply("Done!", chan, nick)
                                        return
                                elif field == "wikipedia":
                                        if not "f" in authtest(host, "#wikipedia", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("UPDATE access SET wikipedia=\'%s\' WHERE cloak=\'%s\';" % (level, specify))
                                        db.commit()
                                        reply("Done!", chan, nick)
                                        return
                                elif field == "other":
                                        if not "f" in authtest(host, "#random", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("UPDATE access SET other=\'%s\' WHERE cloak=\'%s\';" % (level, specify))
                                        db.commit()
                                        reply("Done!", chan, nick)
                                        return
                                elif field == "msg":
                                        if not "f" in authtest(host, "test", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("UPDATE access SET msg=\'%s\' WHERE cloak=\'%s\';" % (level, specify))
                                        db.commit()
                                        reply("Done!", chan, nick)
                                        return
                                else:
                                        reply("You did not specify a valid channel group. (Options: spi, abuse, te, dq" % specify, chan, nick)
                        except Exception:
                                reply("There is no cloak titled \"\x02%s\x0F\"." % specify, chan, nick)
                        return
                elif action == "add":
                        field = string.lower(' '.join(line2[6:]))
                        field = field.split(' ')[0]
                        level = string.lower(' '.join(line2[7:]))
                        if " " in specify: specify = string.split(specify, " ")[0]
                        if not specify or "\"" in specify:
                                reply("Invalid command", chan, nick)
                                return
                        try:
                                if field == "spi":
                                        if not "f" in authtest(host, "#wikipedia-en-spi", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("INSERT INTO access (`cloak`, `spi`, `abuse`, `dq`, `te`, `wikipedia`, `other`, `msg`) VALUES ('%s', '%s', '', '', '', '', '', '');" % (specify, level) )
                                        db.commit()
                                if field == "abuse":
                                        if not "f" in authtest(host, "#wikipedia-en-abuse", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("INSERT INTO access (`cloak`, `spi`, `abuse`, `dq`, `te`, `wikipedia`, `other`, `msg`) VALUES ('%s', '', '%s', '', '', '', '', '');" % (specify, level) )
                                        db.commit()
                                if field == "dq" or field == "deltaquad":
                                        if not "f" in authtest(host, "##DeltaQuad", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("INSERT INTO access (`cloak`, `spi`, `abuse`, `dq`, `te`, `wikipedia`, `other`, `msg`) VALUES ('%s', '', '', '%s', '', '', '', '');" % (specify, level) )
                                        db.commit()
                                if field == "te":
                                        if not "f" in authtest(host, "#techessentials", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("INSERT INTO access (`cloak`, `spi`, `abuse`, `dq`, `te`, `wikipedia`, `other`, `msg`) VALUES ('%s', '', '', '', '%s', '', '', '');" % (specify, level) )
                                        db.commit()
                                if field == "wikipedia":
                                        if not "f" in authtest(host, "#wikipedia", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("INSERT INTO access (`cloak`, `spi`, `abuse`, `dq`, `te`, `wikipedia`, `other`, `msg`) VALUES ('%s', '', '', '', '', '%s', '', '');" % (specify, level) )
                                        db.commit()
                                if field == "other":
                                        if not "f" in authtest(host, "#other", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("INSERT INTO access (`cloak`, `spi`, `abuse`, `dq`, `te`, `wikipedia`, `other`, `msg`) VALUES ('%s', '', '', '', '', '', '%s', '');" % (specify, level) )
                                        db.commit()
                                if field == "msg":
                                        if not "f" in authtest(host, "#other", "no"):
                                                reply("Access Denied, you need the +f (permissions flag) to use this action.", chan, nick)
                                                return
                                        db.query("INSERT INTO access (`cloak`, `spi`, `abuse`, `dq`, `te`, `wikipedia`, `other`, `msg`) VALUES ('%s', '', '', '', '', '', '', '%s');" % (specify, level) )
                                        db.commit()
                                reply("Done!", chan, nick)
                        except Exception:
                                reply("Error.", chan, nick)
                                print traceback.format_exc()
                        return
"""
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
