module SMTP;

@load smtp-decode-encoded-word-subjects.bro

export
    {

    global smtp_debug=open_log_file("smtp-debug");
    global email_domain = /XXXX/ &redef ;

    redef enum Notice::Type += {
        HighNumberRecepients ,
        HighVolumeSender,
        HighVolumeSubject,
        TargetedSubject,
        MailThreshold,
        MailFlood,
        BulkSender,
    };

    type smtp_thresholds: record {
        start_time: time ;
        end_time: time;
        mailfrom: string ;
        from: set[string];
        to: set[string] ;
        rcptto: set[string] ;
        subject: set[string] ;
        reply_to: set[string] ;
        bcc: set[string] ;
        has_url: set[string] ;
        has_attach: set[string] ;
        mail_for: set[string] ;
    };

    global smtp_activity: table[string] of smtp_thresholds &create_expire=10 hrs &persistent;

    type smtp_subjects: record {
        sender: set[string];
        recipients: set[string];
    };

    global smtp_subject_activity: table[string] of smtp_subjects &create_expire=10 hrs &persistent ;

    ## code for threshold determination

    const smtp_threshold: vector of count = {
        200, 300, 500, 750, 1000, 2000, 5000, 7500, 10000, 20000, 50000, 1000000,
    } &redef;

    global smtp_to_threshold_idx: table[string] of count &default=0 &write_expire=1 day &redef;

    const smtp_subject_threshold: vector of count = {
        50, 100, 200, 300, 500, 750, 1000, 2000, 5000, 7500, 10000, 20000, 50000, 1000000,
    } &redef;

    global smtp_subject_threshold_idx: table[string] of count &default=0 &write_expire=1 day &redef;

    ## prepare to digest data from feeds
    type BulkSenderIdx: record {
        mailfrom: string;
    };

    type BulkSenderVal: record {
        mailfrom: string;
        #comment: string &optional &default="null";
    };

    global ok_bulk_sender: table[string] of BulkSenderVal = table() &synchronized &redef;
    global ok_bulk_sender_ip_feed="/usr/local/BRO-feeds/smtp-thresholds::ok_bulk_sender" &redef ;
    global ignore_smtp_subjects: pattern = /phenixbb/ &redef ;
    global SMTP::m_w_email_add: event (rec: SMTP::Info);
    global SMTP::w_m_new_email: event (rec: SMTP::Info);
    global populate_smtp_activity: function(rec: SMTP::Info);
    global site_email: pattern = /@lbl\.gov|@nersc\.gov|@es\.net/ &redef ;

    const SUBJECT_THRESHOLD = 20 ;

    }  #end of export

@if ( Cluster::is_enabled() )
    @load base/frameworks/cluster
    redef Cluster::manager2worker_events += /SMTP::m_w_email_add/;
    redef Cluster::worker2manager_events += /SMTP::w_m_new_email/;
@endif

function check_smtp_threshold(v: vector of count, idx: table[string] of count, orig: string, n: count):bool
    {
    if ( idx[orig] < |v| && n >= v[idx[orig]] )
        {
        ++idx[orig];
        return (T);
        }
    else
        return (F);
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

function clean_sender(sender: string): string
    {

    local pat = />|<| |\"|\'/;
    local to_n = split(sender,/</) ;
    local to_name: string;

    if (|to_n| == 1)
        {
        to_name =  strip(gsub(to_n[1], pat, ""));
        }
    else
        {
        to_name =  strip(gsub(to_n[2], pat, ""));
        }

    to_name=to_lower(to_name);

    return to_name ;

    }

function generate_threshold_notice(mailfrom: string): string
    {

    local duration = duration_to_hour_mins_secs(smtp_activity[mailfrom]$end_time - smtp_activity[mailfrom]$start_time );
    local n = |smtp_activity[mailfrom]$rcptto|;
    local msg = string_cat ("Sender: ", mailfrom, " sent emails to more than: ", fmt("%s", n), " recipients in ", fmt("%s", duration));

    msg += fmt (" ## to: [%s] recipients", |smtp_activity[mailfrom]$to|);
    msg += fmt (" ## rcptto: %s",|smtp_activity[mailfrom]$rcptto|) ;

    if (|smtp_activity[mailfrom]$subject| < SUBJECT_THRESHOLD )
        {
        for (s in smtp_activity[mailfrom]$subject)
            {
            local suber = decode_encoded_word(s);
            msg += fmt (" # subject: [%s] | ", suber );
            }
        }
    else
        msg += fmt (" # subjects: [%s]", |smtp_activity[mailfrom]$subject|);

    msg += fmt (" ## reply_to: %s",|smtp_activity[mailfrom]$reply_to|) ;
    #msg += fmt (" ## bcc: %s",|smtp_activity[mailfrom]$bcc|);
    #msg += fmt (" ## has_url: %s",|smtp_activity[mailfrom]$has_url|);
    #msg += fmt (" ## has_attach: %s",|smtp_activity[mailfrom]$has_attach|);
    #msg += fmt (" ## mail_for: %s",|smtp_activity[mailfrom]$mail_for|);

    return msg ;

    }

function get_site_recipients_count(subject: string): count
    {

    local site_receipient=0;

    for (to in smtp_subject_activity[subject]$recipients)
        {
        if (site_email  in to)
           {
           site_receipient += 1;
            }
        }

    return site_receipient ;

    }

function populate_smtp_activity (rec: SMTP::Info)
    {

    local pat = />|<| |\"|\'/;
    local c = lookup_connection(rec$id);
    local mailfrom = "" ;

    # get the from address of the mailfrom/phisher/spammer

    if (rec?$from)
        {
        mailfrom=rec$from ;
        }
    else if ( rec?$mailfrom )
        {
        mailfrom=strip(gsub(rec$mailfrom, pat, ""));

        if ( mailfrom == ""||mailfrom == "-" || mailfrom =="," )
            {
            mailfrom=rec$from;
            }
        }
    else
        return ;

    local clean_mf = clean_sender(mailfrom);

    if ( clean_mf in ok_bulk_sender)
        {
        return ;
        }

    if (rec?$subject)
        {
        for (a in ok_bulk_sender )
            {
            if (to_lower(a) in to_lower(rec$subject) )
                {
                return;
                }
            }

            local subject = fmt ("%s", rec$subject);
        }

    if (mailfrom !in smtp_activity)
        {
        local activity_rec: smtp_thresholds ;
        smtp_activity[mailfrom]=activity_rec ;
        smtp_activity[mailfrom]$mailfrom=fmt("%s", mailfrom);
        smtp_activity[mailfrom]$start_time=rec$ts ;
        smtp_activity[mailfrom]$to=set();
        smtp_activity[mailfrom]$reply_to=set();
        smtp_activity[mailfrom]$bcc=set();
        smtp_activity[mailfrom]$has_url=set();
        smtp_activity[mailfrom]$has_attach=set();
        smtp_activity[mailfrom]$mail_for=set();
        }

    smtp_activity[mailfrom]$end_time=rec$ts ;

    if (subject !in smtp_subject_activity)
        {
        local subject_rec: smtp_subjects;
        smtp_subject_activity[subject]=subject_rec ;
        smtp_subject_activity[subject]$sender=set();
        smtp_subject_activity[subject]$recipients=set();
        }

    add smtp_subject_activity[subject]$sender[mailfrom];

    local check_thresh = F;
    local check_subject_thresh = F;

    if (rec?$rcptto)
        {
        for (rcptto in rec$rcptto)
            {
            rcptto =  strip(gsub(rcptto, pat, ""));
            rcptto =  to_lower(strip(gsub(rcptto, email_domain, "")));
            rcptto =  strip(gsub(rcptto, email_domain, ""));

            if ( rcptto !in smtp_activity[mailfrom]$rcptto )
                {
                add smtp_activity[mailfrom]$rcptto[rcptto] ;
                }

            if ( rcptto !in smtp_subject_activity[subject]$recipients)
                {
                add smtp_subject_activity[subject]$recipients[rcptto];
                }
            }
        }

    if (rec?$to)
        {
        for (to in rec$to)
            {
            local to_split = split(to,/,/);

            for (every_to in to_split)
                {

                local to_n = split(to_split[every_to],/</) ;
                local to_name: string;

                if (|to_n| == 1)
                    {
                    to_name =  strip(gsub(to_n[1], pat, ""));
                    }
                else
                    {
                    to_name =  strip(gsub(to_n[2], pat, ""));
                    }

                to_name=to_lower(to_name);
                to_name= strip(gsub(to_name, email_domain,""));

                if ( to_name !in smtp_activity[mailfrom]$to )
                    {
                    add smtp_activity[mailfrom]$to[to_name] ;
                    add smtp_subject_activity[subject]$recipients[to_name];
                    }

                if ( to_name !in smtp_subject_activity[subject]$recipients)
                    {
                    add smtp_subject_activity[subject]$recipients[to_name];
                    }

                }
            }
        }

    if (rec?$from)
        {

        local fm=split(rec$from,/</);
        local from: string;

        if (|fm| == 1)
            from=strip(gsub(fm[1],pat,""));
        else
            from=strip(gsub(fm[2],pat,""));

        from=to_lower(from) ;

        if (rec$from !in smtp_activity[mailfrom]$from)
            {
            add smtp_activity[mailfrom]$from[rec$from];
            }
        }

    if (rec?$reply_to)
        {
        local rep_to = split(rec$reply_to,/</) ;
        local reply_to:string ;

        if (|rep_to| == 1)
            {
            reply_to = strip(gsub(rep_to[1],pat,""));
            }
        else
            {
            reply_to = strip(gsub(rep_to[2],pat,""));
            }

        reply_to = to_lower(strip(gsub(reply_to,email_domain, "")));

        if (reply_to !in smtp_activity[mailfrom]$reply_to)
            add smtp_activity[mailfrom]$reply_to[reply_to];
        }

    if (rec?$subject)
        {
        subject = rec$subject ;
        if (subject !in smtp_activity[mailfrom]$subject)
            add smtp_activity[mailfrom]$subject[subject];
        }
    else
        {
        return ;
        }

    local msg = "" ;

    if (check_subject_thresh)
        {
        msg = generate_threshold_notice(mailfrom);

        local site_receipient=0 ;

        site_receipient = get_site_recipients_count(subject);

        local duration = smtp_activity[mailfrom]$end_time - smtp_activity[mailfrom]$start_time ;
        if (site_receipient > SUBJECT_THRESHOLD  && site_email !in mailfrom  )
            {
            msg+= fmt ("number of LBL receipients: %s", site_receipient) ;
            NOTICE([$note=TargetedSubject, $msg=msg]);
            }
        else
            {
            msg+= fmt ("number of LBL receipients: %s", site_receipient) ;
            NOTICE([$note=HighVolumeSubject, $msg=msg]);
            }
        }

    @if (! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ))

        local n = 0 ;
        n = |smtp_activity[mailfrom]$rcptto| ;
        check_thresh =  check_smtp_threshold(smtp_threshold, smtp_to_threshold_idx, mailfrom, n);

        local s = 0 ;
        s = |smtp_subject_activity[subject]$recipients|;
        check_subject_thresh =  check_smtp_threshold(smtp_subject_threshold, smtp_subject_threshold_idx, subject, s);

        if (check_thresh)
            {

            site_receipient=0 ;
            site_receipient = get_site_recipients_count(subject);

            msg = generate_threshold_notice(mailfrom);
            msg+= fmt ("number of LBL receipients: %s", site_receipient) ;

            duration = smtp_activity[mailfrom]$end_time - smtp_activity[mailfrom]$start_time ;

            if (|smtp_activity[mailfrom]$subject| < SUBJECT_THRESHOLD && duration < 5 hrs)
                {
                if (site_email in mailfrom )
                    {
                    NOTICE([$note=HighVolumeSender, $msg=msg]);
                    }
                else
                    {
                    NOTICE([$note=HighNumberRecepients, $msg=msg]);
                    }
                }
            else
                {
                if (site_email in mailfrom )
                    {
                    NOTICE([$note=BulkSender, $msg=msg]);
                    }
                else
                    {
                    NOTICE([$note=MailFlood, $msg=msg]);
                    }
                }

            }

    @endif

    @if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )

        msg =fmt ("inside populae_smtp_activity : %s, %s", rec$uid, rec$subject);
        event reporter_info(current_time(), msg, peer_description);
        event SMTP::w_m_new_email (rec);

    @endif

    }

function check_from_mailfrom(rec: SMTP::Info)
    {

    local mf = rec$mailfrom;
    local f = rec$from;
    local mailfrom=    clean_sender(mf);
    local from=    clean_sender(f);

    }

event bro_init()
    {
    Input::add_table([$source=ok_bulk_sender_ip_feed, $name="bulk_sender", $idx=BulkSenderIdx, $val=BulkSenderVal,  $destination=ok_bulk_sender,
    $mode=Input::REREAD,
    $pred(typ: Input::Event, left: BulkSenderIdx, right: BulkSenderVal) =
        {
        right$mailfrom= clean_sender(right$mailfrom); left$mailfrom= clean_sender(left$mailfrom); return T;
        }
        ]);

    schedule 1 min { force_update_input_logs() };
    }

event SMTP::log_smtp (rec: SMTP::Info) &priority=-5
    {
    if ( connection_exists(rec$id) )
        {
        populate_smtp_activity(rec);
        check_from_mailfrom(rec);
        }
    }  # end of policy

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
    event SMTP::m_w_email_add(rec: SMTP::Info)
        {

        local msg =fmt ("m_w_email_add: %s, %s", rec$uid, rec$subject);
        event reporter_info(current_time(), msg, peer_description);
        #populate_smtp_activity(rec);
        }
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
    event SMTP::w_m_new_email (rec: SMTP::Info)
        {
        local msg =fmt ("w_m_email_new: %s, %s", rec$uid, rec$subject);
        event reporter_info(current_time(), msg, peer_description);

        ## event SMTP::m_w_email_add(rec);
        populate_smtp_activity(rec);
        }
@endif

event force_update_input_logs()
    {
    Input::force_update("bulk_sender");
    schedule 1 min { force_update_input_logs() };
    }

event bro_done()
    {
    }
