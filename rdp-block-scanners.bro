module RDP;

export
    {

    redef enum Notice::Type += {
        BruteforceScan,
        ScanSummary,
    } ;

    global rdp_bruteforcer: table [addr, string] of count &create_expire=1 day &default=0 &redef ;
    global rdp_scanners_account = /a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z/ &redef ;
    redef rdp_scanners_account +=   /A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z/ ;
    redef rdp_scanners_account +=   /NCRACK_USER/ ;

    }

event rdp_connect_request(c: connection, cookie: string) &priority=5
    {

    local orig=c$id$orig_h ;
    local resp=c$id$resp_h ;

    if (cookie == rdp_scanners_account)
        {
        if ( [orig,cookie] !in rdp_bruteforcer)
            {
            rdp_bruteforcer[orig,cookie] = 1  ;

            NOTICE([$note=RDP::BruteforceScan, $src=c$id$orig_h,
                        $msg=fmt("%s bruteforced %s on  RDP (%s) using Account: \"%s\" ", c$id$orig_h, c$id$resp_h, c$id$resp_p, cookie)]);
            }
        else
            rdp_bruteforcer[orig,cookie] += 1  ;
        }

    }


event bro_done()
    {

    for ([scan_addr, cookie] in rdp_bruteforcer)
        {
        NOTICE([$note=RDP::ScanSummary, $src=scan_addr,
                    $msg=fmt("%s bruteforced RDP using Account: \"%s\" %s times ",
                    scan_addr, cookie, |rdp_bruteforcer[scan_addr, cookie]|)]);
        }

    }

