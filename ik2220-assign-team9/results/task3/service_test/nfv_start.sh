#click_dir="/home/mininet/click/userlevel"
click_conf="/home/atiiq/run"
echo "SDNCOURSE : reloading nfv log file"
touch /var/log/idsclick.log
chmod 755 /var/log/idsclick.log
cat /dev/null > /var/log/idsclick.log
touch /var/log/dnsclick.log
chmod 755 /var/log/dnsclick.log
cat /dev/null > /var/log/dnsclick.log
touch /var/log/wwwclick.log
chmod 755 /var/log/wwwclick.log
cat /dev/null > /var/log/wwwclick.log
touch /var/log/natclick.log
chmod 755 /var/log/natclick.log
cat /dev/null > /var/log/natclick.log

#Kill all first
echo "SDNCOURSE : kill all click script"
pkill click

#Run every click instances
echo "SDNCOURSE : starting IDS"
sudo click $click_conf/ids.click >> /var/log/idsclick.log 2>&1 &
echo "SDNCOURSE : starting DNS Load Balancer"
sudo click $click_conf/dns.click >> /var/log/dnsclick.log 2>&1 &
echo "SDNCOURSE : starting WWW Load Balancer"
sudo click $click_conf/www.click >> /var/log/wwwclick.log 2>&1 &
echo "SDNCOURSE : starting NAPT"
sudo click $click_conf/nat.click >> /var/log/natclick.log 2>&1 &
echo "SDNCOURSE : All Click Script are running"
