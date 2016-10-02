// ==================================
// napt click
// Network address and Port Translation
// IK2220 SDN and NFV Assignment
// Team 9
// {atiiq,suryas,purwidi,mnde}@kth.se
// ==================================

// AverageCounter
out_eth1 :: AverageCounter;
out_eth2 :: AverageCounter;
in_eth1 :: AverageCounter;
in_eth2 :: AverageCounter;

// Counter for classifier

// packets
pack_req_ex :: Counter;
pack_res_ex :: Counter;
pack_req_in :: Counter;
pack_res_in :: Counter;

// arp
arp_req_ex :: Counter;
arp_res_ex :: Counter;
arp_req_in :: Counter;
arp_res_in :: Counter;

// Service
service_count :: Counter;

// ICMP
icmp_count :: Counter;
icmp_in :: Counter;
icmp_ex :: Counter;

// Dropped
drop_ex :: Counter;
drop_in :: Counter;
drop_ex_ip :: Counter;
drop_in_ip :: Counter;

// Device declaration
fr_ext :: FromDevice(s10-eth1, SNIFFER false);
to_ext :: Queue(200) -> out_eth1 -> pack_res_ex -> ToDevice(s10-eth1);
fr_int :: FromDevice(s10-eth2, SNIFFER false);
to_int :: Queue(200) -> out_eth2 -> pack_res_in -> ToDevice(s10-eth2);

arpr_ext :: ARPResponder(100.0.0.1 fa:dd:38:74:98:c8);
arpr_int :: ARPResponder(10.0.0.1 52:8f:3e:18:4c:8b);
arpq_ext :: ARPQuerier(100.0.0.1, fa:dd:38:74:98:c8);
arpq_int :: ARPQuerier(10.0.0.1, 52:8f:3e:18:4c:8b);
c_in,c_ex :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
c_ip_in :: IPClassifier(
                        tcp or udp, // Standard Flow
			icmp type 0, // ICMP Response
                        icmp type 8, // ICMP Request
                        - );
c_ip_ex :: IPClassifier(
                        tcp or udp, // Standard Flow
                        icmp type 0, // ICMP Response
                        icmp type 8, // ICMP Request
                        - );
rewr_icmp :: ICMPPingRewriter(pattern 100.0.0.1 50001-55000 - - 0 1);
rewr :: IPRewriter(pattern 100.0.0.1 50001-55000 - - 0 1);

// Statistics for report
// pps
outrate :: Script(TYPE PASSIVE, return $(add $(out_eth1.rate) $(out_eth2.rate)))
inrate :: Script(TYPE PASSIVE, return $(add $(in_eth1.rate) $(in_eth2.rate)))

// packet req-resp
packreq_sum :: Script(TYPE PASSIVE, return $(add $(pack_req_ex.count) $(pack_req_in.count)))
packres_sum :: Script(TYPE PASSIVE, return $(add $(pack_res_ex.count) $(pack_res_in.count)))

// arp req-resp
arpreq_sum :: Script(TYPE PASSIVE, return $(add $(arp_req_ex.count) $(arp_req_in.count)))
arpres_sum :: Script(TYPE PASSIVE, return $(add $(arp_res_ex.count) $(arp_res_in.count)))

// icmp sum
icmp_sum :: Script(TYPE PASSIVE, return $(add $(icmp_count.count) $(icmp_in.count) $(icmp_ex.count)))
// drop sum
drop_sum :: Script(TYPE PASSIVE, return $(add $(drop_ex.count) $(drop_in.count) $(drop_ex_ip.count) $(drop_in_ip.count)))

DriverManager(wait,
                print > napt.report "===============NAPT Report=================",
                print >> napt.report "Input Packet rate (pps) : " $(inrate.run),
                print >> napt.report "Output Packet rate (pps) : " $(outrate.run),
                print >> napt.report " ",
                print >> napt.report "Total # of input packets : " $(packreq_sum.run),
                print >> napt.report "Total # of output packets : "$(packres_sum.run),
                print >> napt.report " ",
                print >> napt.report "Total # of ARP requests : " $(arpreq_sum.run),
                print >> napt.report "Total # of ARP response : " $(arpres_sum.run),
                print >> napt.report " ",
                print >> napt.report "Total # of service packets : "$(service_count.count),
                print >> napt.report "Total # of ICMP packets : "$(icmp_sum.run),
                print >> napt.report "Total # of dropped packets : "$(drop_sum.run),
                print >> napt.report "=========================================",
                print >> napt.report "notes : we consider icmp echo from private network",
		print >> napt.report "NOT as a service",
		stop);

fr_ext -> in_eth1 -> pack_req_ex -> c_in;
c_in[0] -> Print(nat_ci_0) -> arp_req_ex -> arpr_ext[0] -> to_ext;
c_in[1] -> Print(nat_ci_1) -> arp_res_ex -> [1]arpq_ext;
c_in[2] -> Print(nat_ci_2) -> Strip(14) -> CheckIPHeader -> c_ip_in;
c_in[3] -> Print(nat_ci_3) -> drop_ex -> Discard;

c_ip_in[0] -> Print(nat_c_ip_in0) -> rewr[1] -> [0]arpq_int -> to_int;
c_ip_in[1] -> Print(nat_c_ip_in1) -> icmp_ex -> rewr_icmp[1] -> [0]arpq_int -> to_int;
c_ip_in[2] -> Print(nat_c_ip_in2) -> icmp_count -> ICMPPingResponder -> [0]arpq_ext -> to_ext;
c_ip_in[3] -> Print(nat_c_ip_in3) -> drop_ex_ip -> Discard;

fr_int -> in_eth2 -> pack_req_in -> c_ex;
c_ex[0] -> Print(nat_ce_0) -> arp_req_in -> arpr_int[0] -> to_int; 
c_ex[1] -> Print(nat_ce_1) -> arp_res_in -> [1]arpq_int;
c_ex[2] -> Print(nat_ce_2) -> Strip(14) -> CheckIPHeader -> c_ip_ex;
c_ex[3] -> Print(nat_ce_3) -> drop_in -> Discard;

c_ip_ex[0] -> Print(nat_c_ip_ex0) -> service_count -> rewr[0] -> [0]arpq_ext -> to_ext;
c_ip_ex[1] -> Print(nat_c_ip_ex1) -> Discard; 
c_ip_ex[2] -> Print(nat_c_ip_ex2) -> icmp_in -> rewr_icmp[0] -> [0]arpq_ext -> to_ext;
c_ip_ex[3] -> Print(nat_c_ip_ex3) -> drop_in_ip -> Discard;
