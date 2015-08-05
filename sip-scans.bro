
module SIP; 

export 
{

	global sip_scanners: table[addr] of count &redef &read_expire=1 hrs &default=0 ; 
	
	redef enum Notice::Type += {
                SIP_403_Forbidden, 
		SipviciousScan, 
                };


	global malicious_sip: pattern =  /sipvicious|[Ss][Ii][Pp][Vv][Ii][Cc][Ii][Oo][Uu][Ss]|friendly-scanner|nm@nm|nm2@nm2|[Nn][Mm][0-9]@[Nn][Mm][0-9]/ &redef ; 

	global sip_block_codes: set[count] = { 403, 401 } ; 
	global sip_block_reason: pattern = /Forbidden|Unauthorized/ ; 
	
}

event sip_request (c: connection , method: string , original_URI: string , version: string )
{ 

	print fmt ("sip_request: method: %s, URI: %s, version: %s", method, original_URI, version) ; 

} 
event sip_reply (c: connection , version: string , code: count , reason: string )
{ 
	print fmt ("sip_reply: version: %s, code: %s, reason : %s", version, code, reason ); 

	local src=c$id$orig_h ; 
	local dst=c$id$resp_h ; 

	#if (code in sip_block_codes && sip_block_reason in reason) 
	if (code == 403 && sip_block_reason in reason) 
	{ 
		if (src !in sip_scanners)
			sip_scanners[src] = 0 ; 

		sip_scanners[src] += 1; 


		if (sip_scanners[src] > 5) 
		{
			
			 NOTICE([$note=SIP::SIP_403_Forbidden,
                                $conn=c,
                                $suppress_for=6hrs,
                                $msg=fmt("SIP bruteforce: 403 Forbidden"),
                                $identifier=cat(c$id$orig_h)]);
		} 
	} 

} 


event sip_header (c: connection , is_orig: bool , name: string , value: string )
{ 
	print fmt ("sip_header: name :%s, value: %s", name, value); 

	if ( name == "FROM" && malicious_sip in value)
	{
			 NOTICE([$note=SIP::SipviciousScan, 
                                $conn=c,
                                $suppress_for=6hrs,
                                $msg=fmt("Sipvicious Scan seen"),
                                $identifier=cat(c$id$orig_h)]);
	} 
	
	if ( name == "TO" && malicious_sip in value)
	{
			 NOTICE([$note=SIP::SipviciousScan, 
                                $conn=c,
                                $suppress_for=6hrs,
                                $msg=fmt("Sipvicious Scan seen"),
                                $identifier=cat(c$id$orig_h)]);
	} 

	if ( name == "USER-AGENT" && malicious_sip in value)
	{
			 NOTICE([$note=SIP::SipviciousScan, 
                                $conn=c,
                                $suppress_for=6hrs,
                                $msg=fmt("Sipvicious Scan seen"),
                                $identifier=cat(c$id$orig_h)]);
	} 
	
	if ( name == "USER-AGENT" && malicious_sip in value)
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


#sip_request: method: OPTIONS, URI: sip:100@128.3.0.0, version: 2.0
#sip_header: name :VIA, value: SIP/2.0/UDP 149.3.142.10:5251;branch=z9hG4bK-1477480868;rport
#sip_header: name :CONTENT-LENGTH, value: 0
#sip_header: name :FROM, value: "sipvicious"<sip:100@1.1.1.1>;tag=3830303330303030313761630131333132303130313639
#sip_header: name :ACCEPT, value: application/sdp
#sip_header: name :USER-AGENT, value: friendly-scanner
#sip_header: name :TO, value: "sipvicious"<sip:100@1.1.1.1>
#sip_header: name :CONTACT, value: sip:100@149.3.142.10:5251
#sip_header: name :CSEQ, value: 1 OPTIONS
#sip_header: name :CALL-ID, value: 649920334966295388970831
#sip_header: name :MAX-FORWARDS, value: 70
