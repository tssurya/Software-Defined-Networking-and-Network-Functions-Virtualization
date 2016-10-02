// ==================================
// lb2 click
// HTTP Service Load Balancer
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

// Dropped
drop_ex :: Counter;
drop_in :: Counter;

// Device declaration
fr_ext :: FromDevice(s7-eth1, SNIFFER false);
to_ext :: Queue(200) -> out_eth1 -> pack_res_ex -> ToDevice(s7-eth1);
fr_int :: FromDevice(s7-eth2, SNIFFER false);
to_int :: Queue(200) -> out_eth2 -> pack_res_in -> ToDevice(s7-eth2);

// ARP Responder
arpr_ext :: ARPResponder(100.0.0.45 92:4a:f4:04:75:54);
arpr_int :: ARPResponder(100.0.0.45 26:bb:04:96:4b:eb);

// ARP Querier
arpq_ext :: ARPQuerier(100.0.0.45, 92:4a:f4:04:75:54);
arpq_int :: ARPQuerier(100.0.0.45, 26:bb:04:96:4b:eb);

// Classifier internal and external
c_in,c_ex :: Classifier(12/0806 20/0001,	// ARP Request
			12/0806 20/0002,	// ARP Response
			12/0800, 		// IP Packet
			-); 			// the rest
c_ip_in :: IPClassifier(
			dst 100.0.0.45 tcp port 80, 	// http req
			dst 100.0.0.45 and icmp,	// icmp echo req
			- );

rewr :: IPRewriter(weblb);
weblb :: RoundRobinIPMapper(
			100.0.0.45 - 100.0.0.40 - 1 0,	// 1st webserver
			100.0.0.45 - 100.0.0.41 - 1 0,	// 2nd webserver
			100.0.0.45 - 100.0.0.42 - 1 0);	// 3rd webserver

// Statistics for report
// pps
outrate :: Script(TYPE PASSIVE, return $(add $(out_eth1.rate) $(out_eth2.rate)))
inrate :: Script(TYPE PASSIVE, return $(add $(in_eth1.rate) $(in_eth2.rate)))

// arp req-resp
arpreq_sum :: Script(TYPE PASSIVE, return $(add $(arp_req_ex.count) $(arp_req_in.count)))
arpres_sum :: Script(TYPE PASSIVE, return $(add $(arp_res_ex.count) $(arp_res_in.count)))

// packet req-resp
packreq_sum :: Script(TYPE PASSIVE, return $(add $(pack_req_ex.count) $(pack_req_in.count)))
packres_sum :: Script(TYPE PASSIVE, return $(add $(pack_res_ex.count) $(pack_res_in.count)))

// drop sum
drop_sum :: Script(TYPE PASSIVE, return $(add $(drop_ex.count) $(drop_in.count)))

// Driver Manager
DriverManager(wait, 
		print > lb2.report "===============LB2 Report=================",
		print >> lb2.report "Input Packet rate (pps) : " $(inrate.run),
		print >> lb2.report "Output Packet rate (pps) : " $(outrate.run),
		print >> lb2.report " ",
		print >> lb2.report "Total # of input packets : " $(packreq_sum.run),
		print >> lb2.report "Total # of output packets : "$(packres_sum.run),
		print >> lb2.report " ",
		print >> lb2.report "Total # of ARP requests : " $(arpreq_sum.run),
		print >> lb2.report "Total # of ARP response : " $(arpres_sum.run), 
		print >> lb2.report " ",
		print >> lb2.report "Total # of service packets : "$(service_count.count),
		print >> lb2.report "Total # of ICMP packets : "$(icmp_count.count),
		print >> lb2.report "Total # of dropped packets : "$(drop_sum.run),
		print >> lb2.report "=========================================",
		stop);

fr_ext -> in_eth1 -> pack_req_ex -> c_in;
c_in[0] -> Print(www_ci_0) -> arp_req_ex -> arpr_ext[0] -> to_ext;
c_in[1] -> Print(www_ci_1) -> arp_res_ex -> [1]arpq_ext;
c_in[2] -> Print(www_ci_2) -> Strip(14) -> CheckIPHeader -> c_ip_in;
c_in[3] -> Print(www_ci_3) -> Discard;

c_ip_in[0] -> Print(www_c_ip_in0) -> service_count -> rewr[1] -> [0]arpq_int -> to_int;
c_ip_in[1] -> Print(www_c_ip_in1) -> icmp_count -> ICMPPingResponder -> [0]arpq_ext -> to_ext;
c_ip_in[2] -> Print(www_c_ip_in2) -> drop_ex -> Discard;

fr_int -> in_eth2 -> pack_req_in -> c_ex;
c_ex[0] -> Print(www_ce_0) -> arp_req_in -> arpr_int[0] -> to_int; 
c_ex[1] -> Print(www_ce_1) -> arp_res_in -> [1]arpq_int;
c_ex[2] -> Print(www_ce_2) -> Strip(14) -> CheckIPHeader -> rewr[0] -> [0]arpq_ext -> to_ext;
c_ex[3] -> Print(www_ce_3) -> drop_in -> Discard;
