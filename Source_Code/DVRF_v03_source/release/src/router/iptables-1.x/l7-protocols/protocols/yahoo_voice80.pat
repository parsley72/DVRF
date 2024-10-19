# Yahoo messenger - an instant messenger protocol - http://yahoo.com
# Pattern quality: good veryfast
# Protocol groups: proprietary chat
#
# Usually runs on port 5050 
#
# This pattern has been tested and is believed to work well. 
#
# To get or provide more information about this protocol and/or pattern:
# http://www.protocolinfo.org/wiki/Yahoo_Messenger
# http://lists.sourceforge.net/lists/listinfo/l7-filter-developers

# http://www.venkydude.com/articles/yahoo.htm says: 
# All Yahoo commands start with YMSG.  
# (Well... http://ethereal.com/faq.html#q5.32 suggests that YPNS and YHOO
# are also possible, so let's allow those)
# The next 7 bytes contain command (packet?) length and version information
# which we won't currently try to match.
# L means "YAHOO_SERVICE_VERIFY" according to Ethereal
# W means "encryption challenge command" (YAHOO_SERVICE_AUTH)
# T means "login command" (YAHOO_SERVICE_AUTHRESP)
# (there are others, i.e. 0x01 "coming online", 0x02 "going offline",
# 0x04 "changing status to available", 0x06 "user message", but W and T
# should appear in the first few packets.)
# 0xC080 is the standard argument separator, it should appear not long
# after the "type of command" byte.

yahoo_voice80

#^\x80\x67.?.?[/xa0-/x9f]
\x80[\x61\x67g]
