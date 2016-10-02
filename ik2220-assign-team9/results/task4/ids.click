// ==================================
// ids click
// Intrusion Detection System
// IK2220 SDN and NFV Assignment
// Team 9
// {atiiq,suryas,purwidi,mnde}@kth.se
// ==================================

// Source code for IDS

// AverageCounter
out_eth1 :: AverageCounter;
out_eth2 :: AverageCounter;
out_eth3 :: AverageCounter;
in_eth1 :: AverageCounter;
in_eth2 :: AverageCounter;

// Counter for classifier

// packets
pack_req_net :: Counter;
pack_res_net :: Counter;
pack_req_in :: Counter;
pack_res_in :: Counter;
pack_insp :: Counter;

// arp
arp_req_ex :: Counter;
arp_res_ex :: Counter;
//arp_req_in :: Counter;
//arp_res_in :: Counter;

// icmp
icmp_count :: Counter;

// service counter
service_count :: Counter;

// Device declaration
src_net :: FromDevice(s6-eth1, SNIFFER false);
dst_net :: PrioSched -> out_eth1 -> pack_res_net -> ToDevice(s6-eth1);
src_lb :: FromDevice(s6-eth2, SNIFFER false);
dst_lb :: PrioSched -> out_eth2 -> pack_res_in -> ToDevice(s6-eth2);
//src_insp :: FromDevice(s6-eth3, SNIFFER false);
dst_insp :: PrioSched -> out_eth3 -> pack_insp -> ToDevice(s6-eth3);


//FIRST STAGE CLASSIFIER
first_stage :: Classifier(12/0806 20/0001, //ARPreq
                          12/0806 20/0002, //ARPreply
                          12/0800,         //IP packet
                          -);

//SECOND STAGE CLASSIFIER
second_stage :: Classifier(23/01,       //ICMP packets
                           72/48545450, //HTTP PUT/GET packets
                           73/48545450, //HTTP POST
                           47/02,       //SYN
                           47/12,       //SYN ACK
                           47/10,       //ACK
                           47/04,       //RST
                           47/11,       //FIN ACK
                           -);

//THIRD STAGE
third_stage :: Classifier(//66/474554, //GET
                          66/504F5354,  //detect the word POST
                          66/505554,    //detect the word PUT
                          -);
//FOURTH STAGE
fourth_stage :: Classifier(209/636174202f6574632f706173737764,//catpasswd
                           209/636174202f7661722f6c6f672f,    //cat varlog
                           208/494E53455254,                  //INSERT
                           208/555044415445,                  //UPDATE
                           208/44454C455445,                  //DELETE
                           -);

// Statistics for report
// pps
outrate :: Script(TYPE PASSIVE, return $(add $(out_eth1.rate) $(out_eth2.rate) $(out_eth1.rate)))
inrate :: Script(TYPE PASSIVE, return $(add $(in_eth1.rate) $(in_eth2.rate)))

// packet req-resp
packreq_sum :: Script(TYPE PASSIVE, return $(add $(pack_req_net.count) $(pack_req_in.count)))
packres_sum :: Script(TYPE PASSIVE, return $(add $(pack_res_net.count) $(pack_res_in.count) $(pack_insp.count)))

// arp req-resp
// arpreq_sum :: Script(TYPE PASSIVE, return $(add $(arp_req_ex.count) $(arp_req_in.count)))
// arpres_sum :: Script(TYPE PASSIVE, return $(add $(arp_res_ex.count) $(arp_res_in.count)))

DriverManager(wait,
                print > ids.report "===============IDS Report=================",
                print >> ids.report "Input Packet rate (pps) : " $(inrate.run),
                print >> ids.report "Output Packet rate (pps) : " $(outrate.run),
                print >> ids.report " ",
                print >> ids.report "Total # of input packets : " $(packreq_sum.run),
                print >> ids.report "Total # of output packets : "$(packres_sum.run),
                print >> ids.report " ",
                print >> ids.report "Total # of ARP requests : " $(arp_req_ex.count),
                print >> ids.report "Total # of ARP response : " $(arp_res_ex.count),
                print >> ids.report " ",
                print >> ids.report "Total # of service packets : "$(service_count.count),
                print >> ids.report "Total # of ICMP packets : "$(icmp_count.count),
                print >> ids.report "Total # of dropped packets : No dropped packets, malicious packets sent to insp",
                print >> ids.report "=========================================",
                stop);

//FORWARDER FROM INSIDE NETWORK
src_lb -> in_eth2 -> pack_req_in -> Print(ReplyFrInside) -> Queue -> [0]dst_net;
//first_stage_int[0] -> arp_req_in -> Queue -> [0]dst_net;
//first_stage_int[1] -> arp_res_in -> Queue -> [0]dst_net;
//first_stage_int[2] -> Print(ReplyFrInside) -> Queue -> [0]dst_net;

//JUST STUPID FORWARDER. don't forget to comment
//src_net -> Queue -> [0]dst_lb;

//MAIN LOGIC
src_net -> in_eth1 -> pack_req_net -> service_count -> first_stage;
first_stage[0]
        -> Print(1arpreq)
	-> arp_req_ex
        -> Queue
        -> [0]dst_lb;
first_stage[1]
        -> Print(1arprep)
        -> arp_res_ex
	-> Queue
        -> [1]dst_lb;
first_stage[2]
        -> Print(1IPpkt)
        -> second_stage;
first_stage[3]
        -> Print(1other)
        -> Queue
        -> [0]dst_insp;
//=======================================================
second_stage[0]
        -> Print(2icmp)
	-> icmp_count
        -> Queue
        -> [2]dst_lb;
second_stage[1]                 //HTTP
         -> Print(2httpgetput)
         -> third_stage;
second_stage[2]                 //HTTP
         -> Print(2httppost)
         -> third_stage;
second_stage[3]
        -> Print(2syn)
        -> Queue
        -> [3]dst_lb;
second_stage[4]
        -> Print(2synack)
        -> Queue
        -> [4]dst_lb;
second_stage[5]
        -> Print(2ack)
        -> Queue
        -> [5]dst_lb;
second_stage[6]
        -> Print(2rst)
        -> Queue
        -> [6]dst_lb;
second_stage[7]
        -> Print(2finack)
        -> Queue
        -> [7]dst_lb;
second_stage[8]
        -> Print(2other)
        -> Queue
        -> [1]dst_insp;
//==========================================
third_stage[0]
        -> Print(3post)
        -> Queue
        -> [8]dst_lb;
third_stage[1]
	-> Print(3put)
        -> fourth_stage;
third_stage[2]
        -> Print(3other)
        -> Queue
        -> [2]dst_insp;
//=========================================
fourth_stage[0]
        -> Print(4catpwd)
        -> Queue
        -> [3]dst_insp;
fourth_stage[1]
        -> Print(4catvarlog)
        -> Queue
        -> [4]dst_insp;
fourth_stage[2]
        -> Print(4insert)
        -> Queue
        -> [5]dst_insp;
fourth_stage[3]
        -> Print(4update)
        -> Queue
        -> [6]dst_insp;
fourth_stage[4]
        -> Print(4delete)
        -> Queue
        -> [7]dst_insp;
fourth_stage[5]
        -> Print(4PASSYEAY)
        -> Queue
        -> [9]dst_lb;

