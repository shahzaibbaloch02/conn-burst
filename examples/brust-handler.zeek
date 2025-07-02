##! Example event handler for connection bursts

@load ../scripts/main

# Example handler that demonstrates how to respond to connection bursts
event ConnBurst::detected(c: connection, rate_in_mbps: double)
{
    # Print information about the burst
    print fmt("BURST DETECTED: %s:%s -> %s:%s at %.2f Mbps (%s bytes total)",
              c$id$orig_h, c$id$orig_p,
              c$id$resp_h, c$id$resp_p,
              rate_in_mbps,
              c$conn$orig_bytes + c$conn$resp_bytes);
    
    # You could also:
    # - Send alerts to external systems
    # - Log additional information
    # - Take automated response actions
    # - Update threat intelligence feeds
}

# Example of adjusting thresholds
event zeek_init()
{
    # Lower thresholds for more sensitive detection
    ConnBurst::speed_threshold = 25.0;    # 25 Mbps
    ConnBurst::size_threshold = 50.0;     # 50 MB
}