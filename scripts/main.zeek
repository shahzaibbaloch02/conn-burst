##! Identifies connections that are bursting (lots of data and transferring quickly)

module ConnBurst;

export {
    ## The speed threshold in Mbps to consider a connection "bursty"
    const speed_threshold = 50.0 &redef;
    
    ## The size threshold in MB that must be transferred before checking speed
    const size_threshold = 100.0 &redef;
    
    ## Event generated when a bursting connection is detected
    global detected: event(c: connection, rate_in_mbps: double);
    
    ## Log record for connection bursts
    type Info: record {
        ## Timestamp when the burst was detected
        ts: time &log;
        ## Connection UID
        uid: string &log;
        ## Source address
        orig_h: addr &log;
        ## Source port
        orig_p: port &log;
        ## Destination address
        resp_h: addr &log;
        ## Destination port
        resp_p: port &log;
        ## Protocol
        proto: transport_proto &log;
        ## Data rate in Mbps
        rate_mbps: double &log;
        ## Total bytes transferred
        total_bytes: count &log;
        ## Duration of the connection when burst detected
        duration: interval &log;
    };
    
    ## Log stream for connection bursts
    redef enum Log::ID += { LOG };
}

# Track connections we've already identified as bursty
global bursty_conns: set[string] = set();

event zeek_init() &priority=5 {
    Log::create_stream(ConnBurst::LOG, [$columns=Info, $path="conn_burst"]);
}

event connection_state_remove(c: connection) {
    # Clean up tracking
    if ( c$uid in bursty_conns )
        delete bursty_conns[c$uid];
}

event new_connection(c: connection) {
    # Initialize tracking for this connection
    if ( ! c?$conn )
        return;
}

# Check for bursting connections periodically
event ConnBurst::check_connection(c: connection) {
    if ( ! c?$conn )
        return;
        
    # Skip if we already identified this connection as bursty
    if ( c$uid in bursty_conns )
        return;
        
    local conn = c$conn;
    local total_bytes = conn$orig_bytes + conn$resp_bytes;
    
    # Convert bytes to MB
    local total_mb = double_to_count(total_bytes) / 1048576.0;
    
    # Only check connections that have transferred enough data
    if ( total_mb < size_threshold )
        return;
        
    # Calculate duration
    local duration = network_time() - conn$ts;
    if ( duration <= 0.0 )
        return;
        
    # Calculate rate in Mbps (megabits per second)
    local rate_mbps = (total_mb * 8.0) / interval_to_double(duration);
    
    # Check if this connection is bursty
    if ( rate_mbps >= speed_threshold ) {
        # Mark this connection as bursty so we don't check it again
        add bursty_conns[c$uid];
        
        # Generate the event
        event ConnBurst::detected(c, rate_mbps);
        
        # Log the burst
        local rec: ConnBurst::Info = [
            $ts = network_time(),
            $uid = c$uid,
            $orig_h = c$id$orig_h,
            $orig_p = c$id$orig_p,
            $resp_h = c$id$resp_h,
            $resp_p = c$id$resp_p,
            $proto = get_port_transport_proto(c$id$orig_p),
            $rate_mbps = rate_mbps,
            $total_bytes = total_bytes,
            $duration = duration
        ];
        
        Log::write(ConnBurst::LOG, rec);
    }
}

# Schedule periodic checks for active connections
event new_connection(c: connection) &priority=-5 {
    schedule 1.0 sec { ConnBurst::check_connection(c) };
}

# Continue checking connections that aren't bursty yet
event ConnBurst::check_connection(c: connection) &priority=-5 {
    if ( c$uid !in bursty_conns && c?$conn ) {
        # Schedule another check in 1 second
        schedule 1.0 sec { ConnBurst::check_connection(c) };
    }
}