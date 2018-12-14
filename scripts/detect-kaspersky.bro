module Kaspersky;

#@load ./kaspersky_urls.bro 

#redef Config::config_files += { "config/KASPERSKY.ips" };

export {
        redef enum Notice::Type += {
                Mime,     # A kaspersky seen on network 
		URL, 
		IP, 
		ConfigFileReadFail, 
		UserAgent, 
        };

        global watched_resp_mime_types = /application\/x-kaspavupdate|application\/x-kaspavdb/ &redef ; 

	global kaspersky_ips: set[addr]= {37.48.82.67, 94.75.236.123,} &redef ; 
	global watched_kasperksy_urls: pattern &redef ; 



}


event reporter_warning(t: time , msg: string , location: string )
{

        if (/Input::READER_CONFIG: Init: cannot open config\/KASPERSKY.ips/ in msg)
        {
                NOTICE([$note=ConfigFileReadFail, $msg=fmt("%s", msg)]);
        }
}


hook Notice::policy(n: Notice::Info)
{
  if ( n$note == Kaspersky::Mime)
        {
            add n$actions[Notice::ACTION_EMAIL];
        }
  if ( n$note == Kaspersky::URL)
        {
            add n$actions[Notice::ACTION_EMAIL];
        }
  if ( n$note == Kaspersky::IP)
        {
            add n$actions[Notice::ACTION_EMAIL];
        }
  if ( n$note == Kaspersky::UserAgent)
        {
            add n$actions[Notice::ACTION_EMAIL];
        }
}


event HTTP::log_http (rec: HTTP::Info)
{
	if (! rec?$resp_mime_types)
		return ; 

	for (mtypes in rec$resp_mime_types) 
	{ 
	   if (watched_resp_mime_types in rec$resp_mime_types[mtypes]) 
       { 
                	NOTICE([$note=Mime, $id=rec$id, $msg=fmt("Kaspersky %s seen from host %s", rec$resp_mime_types[mtypes], rec$id$orig_h), $identifier=cat(rec$id$orig_h,rec$resp_mime_types[mtypes]),$suppress_for=1 hrs]);
                	NOTICE([$note=UserAgent, $id=rec$id, $msg=fmt("Kaspersky %s seen from host %s", rec$resp_mime_types[mtypes], rec$id$orig_h), $identifier=cat(rec$id$orig_h,rec$resp_mime_types[mtypes]),$suppress_for=1 hrs]);
       } 
	} 
} 

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=-3
{
        local url = HTTP::build_url_http(c$http);
        local message = fmt("%s %s", c$http$method, url);
	local resp_ip = c$id$resp_h ; 

        if ( watched_kasperksy_urls !in unescaped_URI && resp_ip in kaspersky_ips )
        {
         NOTICE([$note=Kaspersky::URL, $msg=message, $conn=c, $identifier=cat(c$id$orig_h,url),$suppress_for=60 min]);
        }

        if ( watched_kasperksy_urls in unescaped_URI && resp_ip !in kaspersky_ips )
        {
         NOTICE([$note=Kaspersky::IP, $msg=message, $conn=c, $identifier=cat(c$id$orig_h,url),$suppress_for=60 min]);
        }

} 

