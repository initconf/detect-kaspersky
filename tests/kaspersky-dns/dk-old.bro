module kaspersky;

export {

	global k_address_space: set[subnet] = { 66.110.49.0/25, } &redef ;
	redef k_address_space += { 	38.117.98.197/32,
					38.117.98.199/32,
					38.117.98.253/32,
					38.124.168.116/32,
					38.124.168.119/32,
					38.124.168.125/32,
					4.28.136.36/32,
					4.28.136.39/32,
					4.28.136.42/32,
					4.28.136.54/32,
					66.110.49.4/32,
					66.110.49.6/32,
				} ; 

}; 

event new_connection (c: connection)
{
	
	
	local ip = c$id$orig_h in Site::local_nets() ? c$id$resp_h : c$id$orig_h;

	if (ip in k_address_space) 
	{ 
		print fmt ("Kaspersky ip seen : %s", orig); 
	} 

} 
