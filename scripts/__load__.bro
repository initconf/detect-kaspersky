#redef exit_only_after_terminate = T;

@load ./detect-kaspersky.bro 
#@load ./config.bro 
@load ./kaspersky_urls.bro

redef  Kaspersky::kaspersky_ips += {80.231.123.131, 193.45.6.7, 4.28.136.42 38.117.98.196 } ; 
