module Persistent ; 

@load base/protocols/conn 
@load base/utils/site.bro
@load policy/misc/profiling.bro

export 
{


	global debug = 0 ; 
	global per_debug = open_log_file("per-debug"); 
	global table_log = open_log_file("per-table"); 

	redef enum Notice::Type += {
		ProlongConversation,
		ShortDelete, 
		MediumDelete, 
		LongDelete, 
		HastyChitChat,
		ProlongChatter, 
		Table_size, 
		Table_Delete, 
		Table_Keep, 
		New_conn, 
		scanner, 
		DurationSpike, 
	};

	type Track_Conn_Record: record {
		 src: addr &optional ;
		 dst: addr &optional ; 
		 first_seen_time: time &optional  ;
		 last_seen: time &optional ;
		 inactive_for: interval &optional &default=0 sec; 
		 conn_count: count &default=0;
		 mean_time_between_conn: interval &default=0 sec; 
		 history: string &optional ; 
		 conn_state: string &optional ; 
		 per_conn_duration: interval ; 

	} ;

	type a_set: record {
	_src: addr; 
	_dst: addr; 
	} ; 

	global idx_set: a_set ; 

	global table_size_count=0 ; 
	

	global remove_stale_conn : function (t: table[addr,addr] of Track_Conn_Record, idx: any): interval; 
	global long_connections: table[addr, addr] of Track_Conn_Record &persistent &create_expire= 0 sec  &expire_func=remove_stale_conn ; 


	global mean_time_between_conn: interval ; 

	global chatty_ports: set[port] = { 53/tcp, 53/udp, 389/tcp }; 
	global SIGMA = 10 ; 
	const LONG_DEL_TIME = 10 hrs ; 
	const MEDIUM_DEL_TIME = 30 secs ; 


	redef enum Log::ID += {Conn_LOG};

	type status : enum { NEW, ONGOING, INACTIVE, EXPIRED, TERMINATED, EXTENDED_INCACHE }; 

	type Info: record {
                ts:   time    &log ;

		src: addr &log &optional ; 
		dst: addr &log &optional  ; 
                note: Notice::Type &log ;
                conn_count: count &log;
		conn_status: status &log &default=NEW; 
		inactive_for: interval &log &optional &default=0 sec; 
		first_seen_time: string &log;
		last_seen: string &log ; 
                mean_time_between_conn: string &log ;
                duration: string &log ;
                
        };

	global log_table: table[addr,addr] of count &write_expire = 1  hrs &default=0 ;

	global bf_scanner: opaque of bloomfilter  ; 

	global conn_history : opaque of bloomfilter ; 


}

function debug_log(m: string)
{

	return ; 
#        print per_debug, fmt ("%s, %s", network_time(), m); 
	#print fmt ("%s", m); 

}


function duration_to_hour_mins_secs(dur: interval): string
{

	if (dur < 0 sec)
		return fmt("%dh%dm%ds",0, 0, 0);

        local dur_count = double_to_count(interval_to_double(dur));
        local hour = dur_count /  3600 ;
        local _mins = dur_count - ((dur_count / 3600 )  * 3600 );
        return fmt("%dh%dm%ds",hour, _mins/60, _mins%60);
}


function log_expire(conn_rec:Track_Conn_Record, duration: string, note: Notice::Type)
{


}


function log_persistent(conn_rec:Track_Conn_Record, duration: string, note: Notice::Type, conn_status: status )
{
	local src = conn_rec$src ;
	local dst = conn_rec$dst ; 

	local info: Info;

	info$ts = conn_rec$last_seen;
	info$src = src ;
	info$dst = dst ;
	info$note= note;
	info$inactive_for=conn_rec$inactive_for;
	info$conn_status=conn_status;
	info$first_seen_time = strftime("%y-%m-%d_%H.%M.%S",conn_rec$first_seen_time);
	info$last_seen = strftime("%y-%m-%d_%H.%M.%S",conn_rec$last_seen) ;
	info$duration = duration ;
	info$conn_count = conn_rec$conn_count ;
	info$mean_time_between_conn = duration_to_hour_mins_secs(conn_rec$mean_time_between_conn) ;

        if ([src, dst] !in log_table)
        {
		if (info$conn_count > 3 ) 
			Log::write(Persistent::Conn_LOG, info );
		
		log_table[src, dst] = 1;
	}
	else if (note == ShortDelete || note == LongDelete || note == MediumDelete) 
	{
			Log::write(Persistent::Conn_LOG, info );
	} 

	
}

function remove_stale_conn(t: table[addr,addr] of Track_Conn_Record, idx: any ): interval
{

	local src: addr; 
	local dst: addr ; 
	local delta: interval ;
	local dt: double;
       	local mtbc: double ;
	
	[src, dst] = idx ; 
	local nt = network_time(); 

	delta = nt -  long_connections[src, dst]$last_seen ;

	dt = interval_to_double(delta);
	mtbc= interval_to_double((long_connections[src, dst]$mean_time_between_conn)) ;
		
	local time_diff = duration_to_hour_mins_secs(long_connections[src, dst]$last_seen - long_connections[src, dst]$first_seen_time); 

	local bloom_idx = fmt ("%s%s", src, dst);

	local rec: Info ; 

	long_connections[src, dst]$inactive_for = network_time () - long_connections[src, dst]$last_seen; 

	if ( (long_connections[src, dst]$mean_time_between_conn <= 0 secs )  && (/S0|OTH/ in long_connections[src, dst]$conn_state ) && (bloomfilter_lookup(bf_scanner, bloom_idx) == 0  ) )
	{
	
		bloomfilter_add(bf_scanner, bloom_idx);
		log_persistent(long_connections[src, dst], time_diff, scanner, INACTIVE);
		return 0 sec ; 
	}
	
	if (( (/S0|OTH/) in long_connections[src, dst]$conn_state )  && delta > MEDIUM_DEL_TIME && long_connections[src, dst]$conn_count == 1  && bloomfilter_lookup(bf_scanner, bloom_idx) <= 3 )
	{
		log_persistent(long_connections[src, dst], time_diff, scanner, INACTIVE);
		bloomfilter_add(bf_scanner, bloom_idx);
		return 0 secs ; 
	}
	

	SIGMA = long_connections[src, dst]$conn_count  ; 

	if ((dt > (SIGMA * mtbc) ) && long_connections[src, dst]$conn_count > 1 )
	{
		log_persistent(long_connections[src, dst], time_diff, ShortDelete, INACTIVE);

		bloomfilter_add(bf_scanner, bloom_idx);
		
		if (debug ==1) 
			print per_debug, fmt ("Deleting : %s", long_connections[src,dst]); 
		
		return 0 secs ; 
	}
	
	if ( delta > LONG_DEL_TIME )
	{
		long_connections[src, dst]$inactive_for = network_time () - long_connections[src, dst]$last_seen;
		
		log_persistent(long_connections[src, dst], time_diff, LongDelete, EXPIRED);

		if (debug ==1) 
			print per_debug, fmt ("Deleting : %s", long_connections[src,dst]); 
		
		return 0 secs ; 
	}


	if (long_connections[src, dst]$mean_time_between_conn == 0 secs && delta > 10 mins )
	{ 
		local ret = 30 mins ; 
		long_connections[src, dst]$inactive_for = network_time () - long_connections[src, dst]$last_seen;
		log_persistent(long_connections[src, dst], time_diff, Table_Keep, EXTENDED_INCACHE);
		return ret ; 
	} 
	else if ( long_connections[src, dst]$mean_time_between_conn > 1 min && long_connections[src, dst]$conn_count > 4 ) 
	{ 
		ret = double_to_interval(SIGMA * mtbc) ; 
		long_connections[src, dst]$inactive_for = network_time () - long_connections[src, dst]$last_seen;
		log_persistent(long_connections[src, dst], time_diff, Table_Keep, EXTENDED_INCACHE);
		return ret ; 
	} 
	else if (long_connections[src, dst]$mean_time_between_conn > 2 hrs )	
	{ 
		long_connections[src, dst]$inactive_for = network_time () - long_connections[src, dst]$last_seen;			
		log_persistent(long_connections[src, dst], time_diff, Table_Keep, EXTENDED_INCACHE);
		return LONG_DEL_TIME; 
	} 		

	ret = 1 min ; 
	return ret ; 

}

event print_table_size() 
{
	return; 

	local original_size = |long_connections|; 
	local msg:string ; 
	
	local byte_size = val_size(long_connections); 

	msg = fmt ("table Bytes: %s , numbers was : %s", byte_size, original_size); 
	##print per_debug, fmt ("table Bytes: %s , numbers was : %s", byte_size, original_size); 
        NOTICE([$note=Table_size, $msg=msg]);

	#schedule 1 min { print_table_size ()}  ; 
} 
 
	

event bro_init()
{

	table_size_count=0 ;
	#schedule 1 min { print_table_size()}  ; 
	
	bf_scanner  = bloomfilter_counting_init(3, 2000000, 1000, "Persistent");
	conn_history = bloomfilter_basic_init(0.0000001, 4000000, "Persistent");
	Log::create_stream(Persistent::Conn_LOG, [$columns=Info]);
} 


event new_connection(c: connection) &priority=-10 
{


} 


function is_failed_conn(c: connection): bool
        {
        if ( (c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_RESET) ||
             (((c$orig$state == TCP_RESET && c$resp$state == TCP_SYN_ACK_SENT) ||
               (c$orig$state == TCP_RESET && c$resp$state == TCP_ESTABLISHED && "S" in c$history )
              ) && /[Dd]/ !in c$history )
           )
                return T;
        return F;
        }

function is_reverse_failed_conn(c: connection): bool
        {
        if ( (c$resp$state == TCP_SYN_SENT && c$orig$state == TCP_RESET) ||
             (((c$resp$state == TCP_RESET && c$orig$state == TCP_SYN_ACK_SENT) ||
               (c$resp$state == TCP_RESET && c$orig$state == TCP_ESTABLISHED && "s" in c$history )
              ) && /[Dd]/ !in c$history )
           )
                return T;
        return F;
        }



event connection_state_remove(c: connection) &priority=-10 
{
	local src = c$id$orig_h;
	local dst = c$id$resp_h ; 

	local msg = "" ; 
	local time_diff: string; 
	local bloom_idx=fmt ("%s-%s", src,dst); 


	if (c$id$resp_p in chatty_ports)
		return ; 

	if (( src in Site::local_nets && dst in Site::local_nets) || src in Site::neighbor_nets || dst in Site::neighbor_nets )
		return ; 
	
	if (is_reverse_failed_conn(c) || is_failed_conn(c) || ( /[Dd]/ !in c$history )) 
	{
		#print per_debug, fmt ("%s failed-conn: %s, %s, %s", c$conn$ts, c$conn$uid, src, dst  );
		return ; 
	} 

	if ([src, dst]  !in long_connections)
	{
	
		local conn_rec: Track_Conn_Record ; 

		conn_rec$src = src ;
		conn_rec$dst = dst ; 
		conn_rec$conn_count = 0 ; 
		conn_rec$first_seen_time = c$start_time ; 
		conn_rec$last_seen = c$start_time ; 
		conn_rec$inactive_for=0 sec; 
		conn_rec$history = c$history ; 
		conn_rec$conn_state = c$conn$conn_state; 
		conn_rec$per_conn_duration = c$duration ; 
		long_connections[src, dst]=conn_rec; 
	} 

	long_connections[src, dst]$conn_count += 1 ;
       	long_connections[src, dst]$last_seen = c$conn$ts; 


	time_diff = duration_to_hour_mins_secs(long_connections[src, dst]$last_seen - long_connections[src, dst]$first_seen_time) ;
	long_connections[src, dst]$inactive_for = network_time () - long_connections[src, dst]$last_seen ; 
       
	long_connections[src, dst]$mean_time_between_conn = (long_connections[src, dst]$last_seen - long_connections[src, dst]$first_seen_time) / long_connections[src, dst]$conn_count ; 
	
	local mtbc = long_connections[src, dst]$mean_time_between_conn ; 
	local last_seen = long_connections[src, dst]$last_seen ; 
	local first_seen = long_connections[src, dst]$first_seen_time ; 
	local conn_count = long_connections[src, dst]$conn_count ; 



	if (c$duration > 1 msec) 
	{ 

	local a = interval_to_double(long_connections[src, dst]$per_conn_duration) ; 

	if ((interval_to_double(c$duration)  > 10 * interval_to_double(long_connections[src, dst]$per_conn_duration/conn_count)) && conn_count > 10 &&mtbc > 0 sec ) 
	{ 
		msg = fmt ("long connections : %s, %s, duration: %s (%s) ", src, dst, time_diff, long_connections[src, dst]);
		#debug_log (fmt ("%s", c));

		#if (debug == 1 )
			#print per_debug, fmt ("SPIKE :: %s, %s, %s, %s, %s", c$duration, long_connections[src, dst]$per_conn_duration, conn_count, a/conn_count, double_to_interval(a/conn_count) ); 

	 	NOTICE([$note=DurationSpike, $conn=c, $msg=msg, $identifier=cat(src, dst)]);
	} 	

	long_connections[src, dst]$per_conn_duration += c$duration; 



	#long_connections[src, dst]$per_conn_duration += double_to_interval(interval_to_double(long_connections[src, dst]$per_conn_duration+c$duration)/conn_count);

		#if (debug == 1 )
		#	print per_debug, fmt (":: %s, %s, %s, %s, %s", c$duration, long_connections[src, dst]$per_conn_duration, conn_count, a/conn_count, double_to_interval(a/conn_count) ); 

	} 

#	if ( (long_connections[src, dst]$last_seen - long_connections[src, dst]$first_seen_time) > 5 mins) 
#	{ 
#		 log_persistent(long_connections[src, dst], time_diff, ProlongConversation, ONGOING);
#
#		local msg = fmt ("long connections : %s, %s, duration: %s (%s) ", src, dst, time_diff, long_connections[src, dst]);
#	 	NOTICE([$note=ProlongConversation, $conn=c, $msg=msg, $identifier=cat(src, dst)]);
#	} 
       
	if (mtbc < 1 sec && mtbc > 0.00001 sec && conn_count > 50)
       	{
		log_persistent(long_connections[src, dst], time_diff, HastyChitChat, ONGOING);
	
                msg = fmt ("HastyChitChat: %s %s, duration: %s (%s) ", src, dst, time_diff, long_connections[src, dst]);

                NOTICE([$note=HastyChitChat, $conn=c, $msg=msg, $identifier=cat(src, dst)]);
        }
	
	if (mtbc < 1 sec && mtbc > 0.00001 sec && conn_count > 2500)
	{

	 	log_persistent(long_connections[src, dst], time_diff, ProlongChatter, ONGOING);
	
                msg = fmt ("Prolonged_ChitChat: %s %s, duration: %s (%s) ", src, dst, time_diff, long_connections[src, dst]);
                NOTICE([$note=ProlongChatter, $conn=c, $msg=msg, $identifier=cat(src, dst)]);
        }
		
	log_persistent(long_connections[src, dst], time_diff, ProlongConversation, ONGOING);

	#debug_log (fmt ("%s, %s, %s", c$conn$ts, c$id, c$duration)); 
} 

event bro_done()
{

	#print fmt ("Size of table is now %s", |long_connections|);
	
}

event conn_state_expire(c: connection)
{


} 
