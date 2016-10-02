m_util="/home/click/mininet/util/m"


# emptying ping.log before further processing

touch /var/log/ping.log
chmod 755 /var/log/ping.log
cp /dev/null /var/log/ping.log

# Test ping
# h1 ping : h2, dnslb, wwwlb, napt
echo "h1(100.0.0.10) ping h2(100.0.0.11)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h1 ping -c 5 100.0.0.11 >> /var/log/ping.log 2>&1
echo "h1(100.0.0.10) ping dnslb(100.0.0.25)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h1 ping -c 5 100.0.0.25 >> /var/log/ping.log 2>&1
echo "h1(100.0.0.10) ping wwwlb(100.0.0.45)" >> /var/log/ping.log 2>&1
sleep 40
$m_util h1 ping -c 30 100.0.0.45 >> /var/log/ping.log 2>&1
echo "h1(100.0.0.10) ping napt(100.0.0.1)" >> /var/log/ping.log 2>&1
sleep 40
$m_util h1 ping -c 5 100.0.0.1 >> /var/log/ping.log 2>&1
echo "h1(100.0.0.10) ping h3(10.0.0.50)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h1 ping -c 5 10.0.0.50 >> /var/log/ping.log 2>&1
echo "h1(100.0.0.10) ping h4(10.0.0.51)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h1 ping -c 5 10.0.0.51 >> /var/log/ping.log 2>&1
echo "h1(100.0.0.10) ping ds1(100.0.0.20)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h1 ping -c 5 100.0.0.20 >> /var/log/ping.log 2>&1
echo "h1(100.0.0.10) ping ws1(100.0.0.40)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h1 ping -c 5 100.0.0.40 >> /var/log/ping.log 2>&1

# h2 ping : h1, dnslb, wwwlb, napt
echo "h2(100.0.0.11) ping h1(100.0.0.10)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h2 ping -c 5 100.0.0.10 >> /var/log/ping.log 2>&1
echo "h2(100.0.0.11) ping dnslb(100.0.0.25)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h2 ping -c 5 100.0.0.25 >> /var/log/ping.log 2>&1
echo "h2(100.0.0.11) ping wwwlb(100.0.0.45)" >> /var/log/ping.log 2>&1
sleep 40
$m_util h2 ping -c 30 100.0.0.45 >> /var/log/ping.log 2>&1
echo "h2(100.0.0.11) ping napt(100.0.0.1)" >> /var/log/ping.log 2>&1
sleep 40
$m_util h2 ping -c 5 100.0.0.1 >> /var/log/ping.log 2>&1
echo "h2(100.0.0.11) ping h3(10.0.0.50)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h2 ping -c 5 10.0.0.50 >> /var/log/ping.log 2>&1
echo "h2(100.0.0.11) ping h4(10.0.0.51)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h2 ping -c 5 10.0.0.51 >> /var/log/ping.log 2>&1
echo "h2(100.0.0.11) ping ds1(100.0.0.20)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h2 ping -c 5 100.0.0.20 >> /var/log/ping.log 2>&1
echo "h2(100.0.0.11) ping ws1(100.0.0.40)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h2 ping -c 5 100.0.0.40 >> /var/log/ping.log 2>&1

# h3 ping : h4, h1, h2, dnslb, wwwlb
echo "h3(10.0.0.50) ping h4(10.0.0.51)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h3 ping -c 5 10.0.0.51 >> /var/log/ping.log 2>&1
echo "h3(10.0.0.50) ping h1(100.0.0.10)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h3 ping -c 5 100.0.0.10 >> /var/log/ping.log 2>&1
echo "h3(10.0.0.50) ping h2(100.0.0.11)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h3 ping -c 5 100.0.0.11 >> /var/log/ping.log 2>&1
echo "h3(10.0.0.50) ping dnslb(100.0.0.25)" >> /var/log/ping.log 2>&1
sleep 40
$m_util h3 ping -c 30 100.0.0.25 >> /var/log/ping.log 2>&1
echo "h3(10.0.0.50) ping wwwlb(100.0.0.45)" >> /var/log/ping.log 2>&1
sleep 60
$m_util h3 ping -c 30 100.0.0.45 >> /var/log/ping.log 2>&1
echo "h3(10.0.0.50) ping ds1(100.0.0.20)" >> /var/log/ping.log 2>&1
sleep 40
$m_util h3 ping -c 5 100.0.0.20 >> /var/log/ping.log 2>&1
echo "h3(10.0.0.50) ping ws1(100.0.0.40)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h3 ping -c 5 100.0.0.40 >> /var/log/ping.log 2>&1


# h4 ping : h3, h1, h2, dnslb, wwwlb
echo "h4(10.0.0.51) ping h3(10.0.0.50)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h4 ping -c 5 10.0.0.50 >> /var/log/ping.log 2>&1
echo "h4(10.0.0.51) ping h1(100.0.0.10)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h4 ping -c 5 100.0.0.10 >> /var/log/ping.log 2>&1
echo "h4(10.0.0.51) ping h2(100.0.0.11)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h4 ping -c 5 100.0.0.11 >> /var/log/ping.log 2>&1
echo "h4(10.0.0.51) ping dnslb(100.0.0.25)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h4 ping -c 5 100.0.0.25 >> /var/log/ping.log 2>&1
echo "h4(10.0.0.51) ping wwwlb(100.0.0.45)" >> /var/log/ping.log 2>&1
sleep 40
$m_util h4 ping -c 30 100.0.0.45 >> /var/log/ping.log 2>&1
echo "h4(10.0.0.51) ping ds1(100.0.0.20)" >> /var/log/ping.log 2>&1
sleep 40
$m_util h4 ping -c 5 100.0.0.20 >> /var/log/ping.log 2>&1
echo "h4(10.0.0.51) ping ws1(100.0.0.40)" >> /var/log/ping.log 2>&1
sleep 5
$m_util h4 ping -c 5 100.0.0.40 >> /var/log/ping.log 2>&1

