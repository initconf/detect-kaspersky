module Kaspersky; 

redef Config::config_files += { "../config/KASPERSKY.ips" }; 

export {

    redef watched_resp_mime_types += /application\/x-kaspavupdate|application\/x-kaspavdb/ ; 
}

event bro_init() {
    #Config::set_value("Kaspersky::kaspersky_ip", );
}

## Note: the data type of 2nd parameter and return type must match
#function change_addr(ID: string, new_value: addr): addr
#    {
#    print fmt("Value of %s changed from %s to %s", ID, testaddr, new_value);
#    return new_value;
#    }
#
#event bro_init()
#    {
#    Option::set_change_handler("TestModule::testaddr", change_addr);
#    }
