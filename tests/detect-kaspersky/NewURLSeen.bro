# @TEST-EXEC: bro -C -r $TRACES/NewURLSeen.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

