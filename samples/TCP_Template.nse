-- Full TCP packet structure with Ethernet and IP headers
local tcpPacket = {
    -- Ethernet header
    eth_dest_mac = {, , , , , },  -- Destination MAC address
    eth_src_mac = {, , , , , },   -- Source MAC address
    ethertype = ,  -- Ethertype for IPv4

    -- IP header
    ip_version_ihl = ,   -- IPv4 version (4) and Internet Header Length (5)
    ip_dscp_ecn = ,      -- Differentiated Services Code Point (DSCP) and Explicit Congestion Notification (ECN)
    ip_total_length = ,  -- Total length of the IP packet
    ip_identification = ,  -- Identification for fragments
    ip_flags_fragment_offset = ,  -- Flags and Fragment Offset
    ip_time_to_live = ,  -- Time to Live (TTL)
    ip_protocol = ,  -- Protocol for the next layer (TCP)
    ip_header_checksum = ,  -- Header checksum (initially 0, will be calculated later)
    ip_source_ip = ,  -- Source IP address (192.168.1.1)
    ip_dest_ip = ,    -- Destination IP address (192.168.1.2)

    -- TCP header
    tcp_sport = ,  -- Source port
    tcp_dport = ,  -- Destination port
    tcp_seq = ,  -- Sequence number
    tcp_ack = ,  -- Acknowledgment number
    tcp_offx2 = ,  -- Data offset and Reserved bits
    tcp_flags = ,  -- TCP flags (SYN)
    tcp_win = ,  -- Window size
    tcp_sum = ,  -- Checksum (initially 0, will be calculated later)
    tcp_urp =    -- Urgent pointer
}