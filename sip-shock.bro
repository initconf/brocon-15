
        redef enum Notice::Type += {
                ## Indicates that a host may have attempted a bash cgi header attack
                SIP_Shock_Attack,
        };

event sip_header(c: connection, is_request: bool, name: string, value: string) &priority=5
        {
	if ( /\x28\x29\x20\x7b\x20/ in value)
	{
                        NOTICE([$note=SIP_Shock_Attack, 
                                $conn=c,
                                $msg=fmt("%s  %s submitting \"%s\"=\"%s\"",c$id$orig_h, c$id$resp_h, name, value),
                                $identifier=c$uid]);
	}
	#print fmt ("name: %s   value: %s", name, value); 
} 
