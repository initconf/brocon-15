
module Shellshock;

@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice


export {
	redef enum Notice::Type += {
		## Indicates that a host may have attempted a bash cgi header attack
		Attempt,
		Hostile_Domain, 
		Hostile_URI, 
		Compromise, 
	};

	const url_regex = /^([a-zA-Z\-]{3,5})(:\/\/[^\/?#"'\r\n><]*)([^?#"'\r\n><]*)([^[:blank:]\r\n"'><]*|\??[^"'\r\n><]*)/ &redef;

	type shellshock_MO: record {
		victim: addr &optional; 
		scanner: set[addr] &optional;
		web_host: string &optional ;
		mal_ips: set[addr] &optional;
		c_and_c: set[addr] &optional;
		culprit_conn: set[conn_id] &optional; 
	} ;
			
	global shellshock_attack: table[string] of shellshock_MO;  
	
}

function find_all_urls(s: string): string_set
    {
    return find_all(s, url_regex);
    }

function extract_host(name: string): string
{
        local split_on_slash = split(name, /\//);
        local num_slash = |split_on_slash|;

## ash
        return split_on_slash[3];
}


event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
{

	if ( is_orig )
		{
		if ( /\x28\x29\x20\x7b\x20/ in value)
		{
			
			NOTICE([$note=Shellshock::Attempt,
				$conn=c,
				$msg=fmt("CVE-2014-6271: %s - %s submitting %s=%s",c$id$orig_h, c$id$resp_h, name, value),
				$identifier=c$uid]);
			
			if (/http/ !in value)
				return ; 

			local links = find_all_urls(value); 
			for (a in links)
			{ 
				local cmd = fmt ("%s", a); 
				local uri = split(cmd,/ /); 
				for (b in uri)
				{  
					if (/http/ in uri[b]) 
					{ 
						local domain = extract_host(uri[b]); 

						if (domain !in shellshock_attack) 
						{
							local rec: shellshock_MO; 

							shellshock_attack[domain] = rec;
							shellshock_attack[domain]$web_host = domain; 
	
							shellshock_attack[domain]$culprit_conn= set(); 
							add shellshock_attack[domain]$culprit_conn[c$id]; 

							shellshock_attack[domain]$mal_ips= set(); 
							add shellshock_attack[domain]$mal_ips[c$id$orig_h]; 
							shellshock_attack[domain]$victim= c$id$resp_h; 
						
					
						}
						
						local m_item: Intel::Item = [$indicator=domain, $indicator_type = Intel::DOMAIN, $meta = [$source = "Shellshock_Script",$do_notice = T] ];
						Intel::insert(m_item);
					
					}
				}  
			} 
				

		}
		}
	
}


event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=10
{

	if (query in shellshock_attack)
	{
		 NOTICE([$note=Shellshock::Hostile_Domain,
                                $conn=c,
                                $msg=fmt("ShellShock Hostile domain seen %s=%s [%s]",c$id$orig_h, c$id$resp_h, query ),
                                $identifier=c$uid]);
	
		add shellshock_attack[query]$mal_ips[c$id$resp_h]; 
	} 
}


event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
{

	print fmt ("DNS_A_REPLY: ans: %s, address: %s",  msg, a); 


} 

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
{


} 

event bro_done()
{

	print fmt ("%s", shellshock_attack); 
}




event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{

	if (c$http$host in shellshock_attack ) 
	{
        	local vuln_url = HTTP::build_url_http(c$http);
		local domain = c$http$host ; 

		NOTICE([$note=Shellshock::Hostile_URI,
                                $conn=c,
                                $msg=fmt("ShellShock Hostile domain seen %s=%s [%s]",c$id$orig_h, c$id$resp_h, c$http$host),
                                $identifier=c$uid, $suppress_for=1 min]);


		#print fmt ("mal_ips: %s", shellshock_attack[domain]$mal_ips); 

		if (c$id$orig_h == shellshock_attack[domain]$victim)
		{
			NOTICE([$note=Shellshock::Compromise ,
					$conn=c,
					$msg=fmt("ShellShock compromise: %s=%s [%s]",c$id$orig_h, c$id$resp_h, vuln_url ),
					$identifier=c$uid]);
		}	
	} 	
}
