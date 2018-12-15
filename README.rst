=================================================================================
Bro package to detect kaspersky anti-virus in your network
=================================================================================

Credits: Special Thanks to Partha Banerjee, LBNL and Michael Smitasin, LBNL 

Following functionality are provided by the script
--------------------------------------------------
::
        1) Alert when Kaspersky anti-virus products are seen in the network
        2) Alert if a New IP or a URL is seen associated with Kaspersky Anti-virus products

Installation
------------
        bro-pkg install bro/initconf/detect-kaspersky
        or
        @load detect-kaspersky/scripts


Detailed Notes:
---------------

Detail Alerts and descriptions: 
*******************************

Heuristics are simple: 
-----------------------
:: 
    1) check for resp_mime_types in the HTTP GET requests to see if its a kaspersky client
        if (watched_resp_mime_types in rec$resp_mime_types[mtypes]) 
        { DO_NOTICE  } 
    2) Use a built in list of  IPs + URLs to identify new Kaspersky IPs and URLs 


This should generate following Kinds of notices:

1) Kaspersky::Mime
-------------------

1544738610.534164       -       192.168.0.8     61681   94.75.236.123   80      -       -       -       tcp     Kaspersky::Mime Kaspersky application/x-kaspavupdate seen from host 192.168.0.8 -       192.168.0.8     94.75.236.12380 -       -       Notice::ACTION_EMAIL,Notice::ACTION_LOG 3600.000000       F       -       -       -       -       -

2) Kaspersky::URL - Note this alert will only fire if a new URL (not seen in scripts/kaspersky_urls.bro ) is seen.

-------------------
1544740085.757819       CHhAvVGS1DHFjwGM9       192.168.0.8     61909   94.75.236.123   80      -       -       -       tcp     Kaspersky::URL  GET http://94.75.236.123/updaters/updater.xml.test      -       192.168.0.8     94.75.236.123   80      -       -       Notice::ACTION_EMAIL,Notice::ACTION_LOG   3600.000000     F       -       -       -       -       -

3) Kaspersky::UserAgent
-------------------
1544740085.916836       -       192.168.0.8     61909   94.75.236.123   80      -       -       -       tcp     Kaspersky::UserAgent    Kaspersky text/html seen from host 192.168.0.8  -       192.168.0.8     94.75.236.123   80      --      Notice::ACTION_EMAIL,Notice::ACTION_LOG 3600.000000     F--       -       -       -

4) Kaspersky::IP - Only  New IPs which are NOT in config/KASPERSKY.ips
-------------------
1544738260.269598       CHhAvVGS1DHFjwGM9       192.168.0.8     61623   1.1.1.1 80      -       -       -       tcp     Kaspersky::IP   GET http://1.1.1.1/updaters/updater.xml.dif     -       192.168.0.8     1.1.1.1 80      -       -Notice::ACTION_EMAIL,Notice::ACTION_LOG        3600.000000


5) Kaspersky::ConfigFileReadFail - Housekeeping alert in case the config file read fails:

-------------------
0.000000        Kaspersky::ConfigFileReadFail   config/KASPERSKY.ips/Input::READER_CONFIG: Init: cannot open config/KASPERSKY.ips       Notice::ACTION_LOG      3600.000000     F       -       -       -       -       -

