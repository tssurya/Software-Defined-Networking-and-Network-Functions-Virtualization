m_util="/home/click/mininet/util/m"
test_dir="/home/atiiq/run"

touch /var/log/resultservice.log
chmod 755 /var/log/resultservice.log
cp /dev/null /var/log/resultservice.log

touch /var/log/service.log
chmod 755 /var/log/service.log
cp /dev/null /var/log/service.log

touch /var/log/servicedns.log
chmod 755 /var/log/servicedns.log
cp /dev/null /var/log/servicedns.log

touch /var/log/servicewww.log
chmod 755 /var/log/servicewww.log
cp /dev/null /var/log/servicewww.log


#============================================================================
#DNS SERVER TEST
#H1
echo "h1 digging 100.0.0.25 for sdncourse.se" >> /var/log/service.log 2>&1
$m_util h1 timeout 20 dig @100.0.0.25 sdncourse.se >> /var/log/servicedns.log 2>&1
sleep 5
#H2
echo "h2 digging 100.0.0.25 for sdncourse.se" >> /var/log/service.log 2>&1
$m_util h2 timeout 20 dig @100.0.0.25 sdncourse.se >> /var/log/servicedns.log 2>&1
sleep 5
#H3
echo "h3 digging 100.0.0.25 for sdncourse.se" >> /var/log/service.log 2>&1
$m_util h3 timeout 20 dig @100.0.0.25 sdncourse.se >> /var/log/servicedns.log 2>&1
sleep 5
#H4
echo "h4 digging 100.0.0.25 for sdncourse.se" >> /var/log/service.log 2>&1
$m_util h4 timeout 20 dig @100.0.0.25 sdncourse.se >> /var/log/servicedns.log 2>&1
sleep 10
python $test_dir/servdnschecker.py

#============================================================================
#WWW SERVER TEST
echo "h1 curl sdncourse.se" >> /var/log/service.log 2>&1
$m_util h1 timeout 20 curl sdncourse.se -s -X POST -v >> /var/log/servicewww.log 2>&1
sleep 5
echo "h2 curl sdncourse.se" >> /var/log/service.log 2>&1
$m_util h2 timeout 20 curl sdncourse.se -s -X POST -v >> /var/log/servicewww.log 2>&1
sleep 5
echo "h3 curl sdncourse.se" >> /var/log/service.log 2>&1
$m_util h3 timeout 20 curl sdncourse.se -s -X POST -v >> /var/log/servicewww.log 2>&1
sleep 5
echo "h4 curl sdncourse.se" >> /var/log/service.log 2>&1
$m_util h4 timeout 20 curl sdncourse.se -s -X POST -v >> /var/log/servicewww.log 2>&1
sleep 10
python $test_dir/servwwwchecker.py


#============================================================================
#WWW LB ROUND ROBIN TEST 
echo "WWW LB ROUND ROBIN TEST" >> /var/log/service.log 2>&1
$m_util s7 tcpdump -i s7-eth1 -w $test_dir/71.pcap 2>&1 &
$m_util s7 tcpdump -i s7-eth2 -w $test_dir/72.pcap 2>&1 &
$m_util h1 timeout 20 curl 100.0.0.45 -X POST -s -v >> /var/log/service.log 2>&1
sleep 20
$m_util h1 timeout 20 curl 100.0.0.45 -X POST -s -v >> /var/log/service.log 2>&1
sleep 20
$m_util h1 timeout 20 curl 100.0.0.45 -X POST -s -v >> /var/log/service.log 2>&1
sleep 20
$m_util h1 timeout 20 curl 100.0.0.45 -X POST -s -v >> /var/log/service.log 2>&1
sleep 20
$m_util h1 timeout 20 curl 100.0.0.45 -X POST -s -v >> /var/log/service.log 2>&1
sleep 20
$m_util h1 timeout 20 curl 100.0.0.45 -X POST -s -v >> /var/log/service.log 2>&1
pkill tcp
python $test_dir/rrdnschecker.py
sleep 20

#============================================================================
#IDS TEST

echo "IDS TEST : Allowed packets" >> /var/log/service.log 2>&1
echo "1. ARP & PING" >> /var/log/service.log 2>&1
$m_util s6 tcpdump -i s6-eth1 -w $test_dir/61.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth2 -w $test_dir/62.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth3 -w $test_dir/63.pcap 2>&1 &
$m_util h11 tcpdump -i h11-eth0 -w $test_dir/insptest1.pcap 2>&1 &
$m_util h1 ping 100.0.0.45 -c 10 >> /var/log/service.log 2>&1 
pkill tcp
killall tcp
python $test_dir/analyzer1.py
sleep 5

echo "2. HTTP POST" >> /var/log/service.log 2>&1
$m_util s6 tcpdump -i s6-eth1 -w $test_dir/61.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth2 -w $test_dir/62.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth3 -w $test_dir/63.pcap 2>&1 &
$m_util h11 tcpdump -i h11-eth0 -w $test_dir/insptest2.pcap 2>&1 &
$m_util h1 timeout 20 curl 100.0.0.45 -X POST -v -d 'user=foo' >> /var/log/service.log 2>&1
pkill tcp
killall tcp
python $test_dir/analyzer2.py
sleep 5

echo "3. HTTP PUT" >> /var/log/service.log 2>&1
$m_util s6 tcpdump -i s6-eth1 -w $test_dir/61.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth2 -w $test_dir/62.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth3 -w $test_dir/63.pcap 2>&1 &
$m_util h11 tcpdump -i h11-eth0 -w $test_dir/insptest3.pcap 2>&1 &
$m_util h1 timeout 20 curl 100.0.0.45 -X PUT -v -d 'HelloWorld' >> /var/log/service.log 2>&1
pkill tcp
python $test_dir/analyzer3.py
sleep 5

echo "IDS TEST : Blocked packets" >> /var/log/service.log 2>&1
echo "4. HTTP PUT injection" >> /var/log/service.log 2>&1
$m_util s6 tcpdump -i s6-eth1 -w $test_dir/61.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth2 -w $test_dir/62.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth3 -w $test_dir/63.pcap 2>&1 &
$m_util h11 tcpdump -i h11-eth0 -w $test_dir/insptest4.pcap 2>&1 &
$m_util h1 timeout 15 curl 100.0.0.45 -X PUT -v -d \"cat /etc/passwd\" >> /var/log/service.log 2>&1
$m_util h1 timeout 15 curl 100.0.0.45 -X PUT -v -d \"cat /var/log/\" >> /var/log/service.log 2>&1
$m_util h1 timeout 15 curl 100.0.0.45 -X PUT -v -d 'INSERT' >> /var/log/service.log 2>&1
$m_util h1 timeout 15 curl 100.0.0.45 -X PUT -v -d 'UPDATE' >> /var/log/service.log 2>&1
$m_util h1 timeout 15 curl 100.0.0.45 -X PUT -v -d 'DELETE' >> /var/log/service.log 2>&1
kill tcp
python $test_dir/analyzer4.py
sleep 5

echo "5. HTTP GET" >> /var/log/service.log 2>&1
$m_util s6 tcpdump -i s6-eth1 -w $test_dir/61.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth2 -w $test_dir/62.pcap 2>&1 &
$m_util s6 tcpdump -i s6-eth3 -w $test_dir/63.pcap 2>&1 &
$m_util h11 tcpdump -i h11-eth0 -w $test_dir/insptest5.pcap 2>&1 &
$m_util h1 timeout 20 wget -O - 100.0.0.45 >> /var/log/service.log 2>&1
pkill tcp
python $test_dir/analyzer5.py

#============================================================================
