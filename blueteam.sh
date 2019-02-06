#!/bin/bash

clear && echo "Updating OS"
apt-get update && apt-get upgrade -y
clear && echo "Installing apt packages"
apt-get install -y open-vm-tools open-vm-tools-desktop git openjdk-8-jdk wget apt-transport-https

clear && echo "Cloning repositories"
cd /opt/
git clone https://github.com/volatilityfoundation/volatility
git clone https://github.com/Neo23x0/sigma

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-6.x.list
apt-get update

# 1 - elasticsearch
clear && echo "Installing Elasitcsearch"
apt-get install elasticsearch
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl start elasticsearch.service
#config:/etc/elasticsearch/elasticsearch.yml

# 2 - kibana
clear && echo "Installing Kibana"
apt-get install kibana
systemctl daemon-reload
systemctl enable kibana.service
systemctl start kibana.service
#config: /etc/kibana/kibana.yml
sed -i 's/#server.port: 5601/server.port: 5601/g' /etc/kibana/kibana.yml
sed -i 's/#server.host: "localhost"/server.host: "0.0.0.0"/g' /etc/kibana/kibana.yml

# 3 - logstash
clear && echo "Installing Logstash"
apt-get install logstash
systemctl daemon-reload
systemctl enable logstash.service
systemctl start logstash.service
#config: /etc/logstash/logstash.yml

# 4 - beats
#clear && echo "Installing Beats"
#apt-get install -y auditbeat filebeat heartbeat metricbeat packetbeat
#systemctl daemon-reload
#systemctl enable auditbeat.service
#systemctl start auditbeat.service
#systemctl enable filebeat.service
#systemctl start filebeat.service
#systemctl enable heartbeat.service
#systemctl start heartbeat.service
#systemctl enable metricbeat.service
#systemctl start metricbeat.service
#systemctl enable packetbeat.service
#systemctl start packetbeat.service

#kibana app
bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Kibana\nExec=firefox http://localhost:5601\nIcon=/usr/share/kibana/src/ui/public/assets/favicons/apple-touch-icon.png\nCategories=Application;' > /usr/share/applications/kibana.desktop"

#sigma
clear && echo "Installing sigma"
cd /opt/sigma/
apt-get install -y python3-pip
pip3 install sigmatools

apt autoremove -y

cd /opt/
clear
echo "Done."
read -p "Press Enter to continue." </dev/tty