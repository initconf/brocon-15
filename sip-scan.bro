@load base/utils/files

module Conn;

export {

	global sip_scanner_counter: table[addr] of set[addr]  &read_expire = 1 days &redef;
        global identified_sip_scanner: set [addr];

	const sip_threshold: vector of count = {
                  100, 500, 1000, 2000, 10000, 20000, 50000, 100000, 
        } &redef;
	
	global sip_ip_idx: table[addr] of count
                        &default=0 &read_expire = 1 day &redef;
}


function check_ip_threshold(v: vector of count, idx: table[addr] of count, orig: addr, n: count):bool
{

#print fmt ("orig: %s and IDX_orig: %s and n is: %s and v[idx[orig]] is: %s", orig, idx[orig], n, v[idx[orig]]);
 if ( idx[orig] < |v| && n >= v[idx[orig]] )
                {
                ++idx[orig];

                return (T);
                }
        else
                return (F);
}



function check_sip_scan( c: connection) 
{


        local src = c$id$orig_h;
        local dst = c$id$resp_h;
        local src_p = c$id$orig_p;
        local dst_p = c$id$resp_p ;

#        if (src in identified_sip_scanner)
#                return;

##        if ( dst_p == 5060/udp)
        if (!Site::is_local_addr(src) && dst_p == 5060/udp)
        {
                 if (src !in sip_scanner_counter)  {
                        sip_scanner_counter[src] = set();
                }

                if ( dst !in sip_scanner_counter[src] )
                        add sip_scanner_counter[src][dst];

        local n = |sip_scanner_counter[src]| ;
        local svc = 5060/udp ;

	local check_thresh =  check_ip_threshold(sip_threshold, sip_ip_idx, src, n); 

		if (check_thresh) {
			NOTICE([$note=Scan::AddressScan, $src=src, $p=svc, $n=n, $msg=fmt("%s has scanned %d hosts (%s)", src, n, svc)]);
			add identified_sip_scanner[src] ;
		}
        }

} 

event connection_established(c: connection) &priority=-5
{

	check_sip_scan(c); 	

}


event connection_state_remove(c: connection) {

        check_sip_scan(c);

}

event connection_established(c: connection)
{

        check_sip_scan(c);

}

event connection_attempt(c: connection)
{

        check_sip_scan(c);

}
event connection_half_finished(c: connection)
{

        check_sip_scan(c);

}
event connection_rejected(c: connection)
{

        check_sip_scan(c);

}
event connection_reset(c: connection)
{

        check_sip_scan(c);

}
event connection_pending(c: connection)
{

        check_sip_scan(c);

}
