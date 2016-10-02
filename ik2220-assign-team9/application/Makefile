app:
	sudo /home/click/pox/pox.py log.level --DEBUG sdn/controller.py >> /var/log/pox.log 2>&1 &
	sudo click nfv/ids.click >> /var/log/idsclick.log 2>&1 &
	sudo click nfv/dns.click >> /var/log/dnsclick.log 2>&1 &
	sudo click nfv/www.click >> /var/log/wwwclick.log 2>&1 &
	sudo click nfv/nat.click >> /var/log/natclick.log 2>&1 &

clean:
	sudo pkill pox
	sudo killall click	
