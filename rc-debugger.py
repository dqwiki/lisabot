import traceback, re, time
def updateRC():
        #f = open('C:\\wamp\\www\\lisabot\\rcstalklist.txt','r')
        f = open('rcstalklist.txt','r')
        stalk=f.read()
        f.close()
        #f = open('C:\\wamp\\www\\lisabot\\rcblacklist.txt','r')
        f = open('rcblacklist.txt','r')
        black = f.read()
        f.close()
        stalk,black=stalk.split("\n"),black.split("\n")
        return stalk,black
stalk,black = updateRC()
print stalk,black
page,user,summary = "Wikipedia:Sockpuppet investigations/Cases/Overview","Amalthea (bot)","Update SPI case overview (58 open cases) ([[User:Amalthea (bot)#III|III]])"
channel = "#wikipedia-en-spi"
method = "page"
alreadyprint=""
def check(stalk,black,page,user,summary,channel,method,alreadyprint):
    if method == "page":
        print "-----------Match page------------------"
        try:
            for bline in black:
                if bline =="" or "\n" in bline:continue
                print bline
                bline=bline.split(",")
                if (bline[1] in page or bline[1] in user or bline[1] in summary) and bline[0] == channel:
                    print "BLACKLIST"
                    print "!!! This ^^ ("+' '.join(bline[0:])+") bline RC entry is blacklisted. !!!"
                    return
            if channel not in alreadyprint:print "ISAID"#say(msg, channel)
            time.sleep(0.5)
            alreadyprint = alreadyprint + "," + channel
            print "-----------END1------------"
        except:
            print "Error in page stalking post, please refer to the following:"
            trace = traceback.format_exc() # Traceback.
            print trace # Print.
            print "----------END-------------"
check(stalk,black,page,user,summary,channel,method,alreadyprint)
