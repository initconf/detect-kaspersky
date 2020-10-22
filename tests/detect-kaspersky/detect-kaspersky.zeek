# @TEST-EXEC: zeek -C -r $TRACES/detect-kaspersky.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

