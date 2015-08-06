module SIP;

export
{

        global sip_scanners: table[addr] of count &redef &read_expire=1 hrs &default=0 ;

        const BLOCK_THRESHOLD=5 ;

        redef enum Notice::Type += {
                SIP_403_Forbidden,
                SipviciousScan,
                };

        global malicious_sip: pattern = /sipvicious|[Ss][Ii][Pp][Vv][Ii][Cc][Ii][Oo][Uu][Ss]
                                        |friendly-scanner|nm@nm|nm2@nm2|[Nn][Mm][0-9]@[Nn][Mm][0-9]/ &redef ;

        global sip_block_codes: set[count] = { 403, 401 } ;
        global sip_block_reason: pattern = /Forbidden|Unauthorized/ ;

}

event sip_reply (c: connection , version: string , code: count , reason: string )
{
        local src=c$id$orig_h ;
        local dst=c$id$resp_h ;

        if (code == 403 && sip_block_reason in reason)
        {
                if (src !in sip_scanners)
                        sip_scanners[src] = 0 ;

                sip_scanners[src] += 1;

                if (sip_scanners[src] > BLOCK_THRESHOLD )
                {
                         NOTICE([$note=SIP::SIP_403_Forbidden,
                                $conn=c,
                                $suppress_for=6hrs,
                                $msg=fmt("SIP bruteforce: 403 Forbidden"),
                                $identifier=cat(c$id$orig_h)]);
                }
        }

}

#if (code in sip_block_codes && sip_block_reason in reason)

event sip_header (c: connection , is_orig: bool , name: string , value: string )
{
        print fmt ("sip_header: name :%s, value: %s", name, value);

        if (( name == "FROM" || name == "TO" || name == "USER-AGENT")  && malicious_sip in value)) 
        {
                         NOTICE([$note=SIP::SipviciousScan,
                                $conn=c,
                                $suppress_for=6hrs,
                                $msg=fmt("Sipvicious Scan seen"),
                                $identifier=cat(c$id$orig_h)]);
        }
}


event sip_all_headers (c: connection , is_orig: bool , hlist: mime_header_list )
{

        print fmt ("sip_all_headers: %s", mime_header_list );


}
event sip_begin_entity (c: connection , is_orig: bool )
{ }
event sip_end_entity (c: connection , is_orig: bool )
{ }

event sip_request (c: connection , method: string , original_URI: string , version: string )
{
        print fmt ("sip_request: method: %s, URI: %s, version: %s", method, original_URI, version) ;
}

