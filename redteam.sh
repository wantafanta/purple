#!/bin/bash

URL_BLOODHOUND='https://github.com/BloodHoundAD/BloodHound/releases/download/2.1.0/BloodHound-linux-x64.zip'
URL_BETTERCAP='https://github.com/bettercap/bettercap/releases/download/v2.19/bettercap_linux_amd64_2.19.zip'
URL_GOWITNESS='https://github.com/sensepost/gowitness/releases/download/1.0.8/gowitness-linux-amd64'
URL_RULER='https://github.com/sensepost/ruler/releases/download/2.2.0/ruler-linux64'
URL_HASHCAT='https://github.com/hashcat/hashcat/releases/download/v5.1.0/hashcat-5.1.0.7z'
URL_HASHCAT_UTILS='https://github.com/hashcat/hashcat-utils/releases/download/v1.9/hashcat-utils-1.9.7z'
URL_DBEAVER='https://dbeaver.io/files/dbeaver-ce_latest_amd64.deb'
URL_COWPATTY='http://www.willhackforsushi.com/code/cowpatty/4.6/cowpatty-4.6.tgz'
URL_DIRBUSTER_LISTS='https://netix.dl.sourceforge.net/project/dirbuster/DirBuster%20Lists/Current/DirBuster-Lists.tar.bz2'
URL_SHELLTER='https://www.shellterproject.com/Downloads/Shellter/Latest/shellter.zip'
URL_SHELLTER_README='https://www.shellterproject.com/Downloads/Shellter/Readme.txt'
URL_MERLIN='https://github.com/Ne0nd0g/merlin/releases/download/v0.6.4/merlinServer-Linux-x64-v0.6.4.BETA.7z'

clear
RUID=$(who | awk 'FNR == 1 {print $1}')
RUSER_UID=$(id -u ${RUID})
chown -R ${RUID}:${RUID} /opt/

clear && echo "Updating OS"
apt-get update && apt-get upgrade -y
clear && echo "Installing apt packages"
apt-get install -y open-vm-tools open-vm-tools-desktop net-tools git tmux whois ipcalc curl python-pip python3-pip python-qt4 libcanberra-gtk-module libgconf-2-4

clear && echo "Configuring TMUX"
echo 'set -g default-terminal "screen-256color"' > ~/.tmux.conf
chown -R ${RUID}:${RUID} ~/.tmux.conf

clear && echo "Installing Firewall"
apt install -y gufw
ufw disable

clear && echo "Installing nmap/zenmap"
apt-get install -y nmap zenmap
wget 'https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse' -O '/usr/share/nmap/scripts/vulners.nse'
git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/
mkdir '/usr/share/nmap/scripts/vulscan/'
wget 'http://www.computec.ch/projekte/vulscan/download/cve.csv' -o '/usr/share/nmap/scripts/vulscan/cve.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/exploitdb.csv' -o '/usr/share/nmap/scripts/vulscan/exploitdb.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/openvas.csv' -o '/usr/share/nmap/scripts/vulscan/openvas.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/osvdb.csv' -o '/usr/share/nmap/scripts/vulscan/osvdb.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/scipvuldb.csv' -o '/usr/share/nmap/scripts/vulscan/scipvuldb.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/securityfocus.csv' -o '/usr/share/nmap/scripts/vulscan/securityfocus.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/securitytracker.csv' -o '/usr/share/nmap/scripts/vulscan/securitytracker.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/xforce.csv' -o '/usr/share/nmap/scripts/vulscan/xforce.csv'
nmap --script-updatedb

clear && echo "Installing snaps"
snap install powershell --classic
snap install docker
snap install remmina
snap connect remmina:avahi-observe :avahi-observe
snap connect remmina:cups-control :cups-control
snap connect remmina:mount-observe :mount-observe
snap connect remmina:password-manager-service :password-manager-service
snap install john-the-ripper

clear && echo "Installing pips"
python -m pip install --user pipenv
python -m pip install service_identity rdpy

clear && echo "Cloning repositories"
cd /opt/
git clone --recursive https://github.com/byt3bl33d3r/crackmapexec
git clone https://github.com/rbsec/dnscan
git clone https://github.com/byt3bl33d3r/deathstar
git clone https://github.com/byt3bl33d3r/silenttrinity
git clone https://github.com/EmpireProject/empire --branch dev
git clone https://github.com/fox-it/mitm6
git clone https://github.com/BloodHoundAD/bloodhound
git clone https://github.com/SpiderLabs/responder
git clone https://github.com/CoreSecurity/impacket
git clone https://github.com/susmithHCK/torghost
git clone https://github.com/insecurityofthings/jackit
git clone https://github.com/lightos/credmap
git clone https://github.com/jseidl/usernamer
git clone https://github.com/BishopFox/spoofcheck
git clone https://github.com/FluxionNetwork/fluxion
git clone https://gitlab.com/initstring/evil-ssdp
git clone https://github.com/actuated/msf-exploit-loop
git clone https://github.com/dafthack/mailsniper
git clone https://github.com/beefproject/beef
git clone https://github.com/RUB-NDS/pret
git clone https://github.com/laramies/theharvester
git clone --depth 1 https://github.com/danielmiessler/seclists
git clone https://github.com/D4Vinci/cr3dov3r
git clone https://github.com/vysec/linkedint
git clone https://github.com/SimplySecurity/simplyemail
git clone https://github.com/SySS-Research/seth
git clone https://github.com/dirkjanm/privexchange #httpattack.py must be configured
git clone https://github.com/m8r0wn/nullinux
git clone https://github.com/m8r0wn/enumdb
git clone https://github.com/m8r0wn/pymeta
git clone https://github.com/trustedsec/unicorn
git clone https://github.com/Pepelux/sippts
git clone https://github.com/21y4d/nmapautomator

#cd /opt and run the below to update all repositories
#ls | xargs -I{} git -C {} pull

#-- PRIVILEGE ESCALATION
git clone https://github.com/PowerShellMafia/powersploit
git clone https://github.com/GDSSecurity/windows-exploit-suggester
git clone https://github.com/mzet-/linux-exploit-suggester
git clone https://github.com/diego-treitos/linux-smart-enumeration

#-- DESKTOP LINKS
bash -c "echo -e '[Desktop Entry]\nEncoding=UTF-8\nName=Link to LOLBAS\nType=Link\nURL=https://lolbas-project.github.io/#\nIcon=text-html' > /home/${RUID}/Desktop/LOLBAS.desktop"
bash -c "echo -e '[Desktop Entry]\nEncoding=UTF-8\nName=Link to GTFOBins\nType=Link\nURL=https://gtfobins.github.io/\nIcon=text-html' > /home/${RUID}/Desktop/GTFOBins.desktop"
chown -R ${RUID}:${RUID} /home/${RUID}/Desktop/*.desktop

#-- BASH ALIASES
bash -c "echo -e 'alias cameradar=\"sudo docker run -t ullaakut/cameradar\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias deathstar=\"/opt/deathstar/DeathStar.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias dnscan=\"/opt/dnscan/dnscan.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias enumdb=\"/opt/enumdb/enumdb.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias evil-ssdp=\"/opt/evil-ssdp/evil_ssdp.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias gowitness=\"/opt/gowitness/gowitness-linux-amd64\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias nmapautomator=\"sudo /opt/nmapautomator/nmapAutomator.sh\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias pret=\"/opt/pret/pret.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias pymeta=\"/opt/pymeta/pymeta.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias responder=\"sudo /opt/responder/Responder.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias ruler=\"/opt/ruler/ruler-linux64\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias seth=\"/opt/seth/seth.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias spoofcheck=\"/opt/spoofcheck/spoofcheck.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias theharvester=\"/opt/theharvester/theHarvester.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias unicorn=\"/opt/unicorn/unicorn.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias usernamer=\"/opt/usernamer/usernamer.py\"' >> /home/${RUID}/.bash_aliases"
#. ~/.bashrc

clear && echo "Installing Metasploit"
apt-get install -y postgresql
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
rm msfinstall
cd /opt/metasploit-framework/
wget 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/lib/msf/core/web_services/public/favicon.ico' -O logo.ico
bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Metasploit Framework\nExec=gnome-terminal --window -- sudo msfconsole\nIcon=/opt/metasploit-framework/logo.ico\nCategories=Application;' > /usr/share/applications/metasploit-framework.desktop"
cp /opt/metasploit-framework/embedded/framework/config/database.yml.example /opt/metasploit-framework/embedded/framework/config/database.yml
sed -i 's/^  password:.*/  password: msf/g' /opt/metasploit-framework/embedded/framework/config/database.yml
sudo -u postgres bash -c "psql -c \"CREATE USER metasploit_framework_development WITH PASSWORD 'msf';\""
sudo -u postgres bash -c "psql -c \"CREATE DATABASE metasploit_framework_development;\""
sudo -u postgres bash -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE metasploit_framework_development TO metasploit_framework_development;\""

clear && echo "Installing searchsploit"
git clone --depth 1 https://github.com/offensive-security/exploitdb.git /opt/exploitdb
sed 's|path_array+=(.*)|path_array+=("/opt/exploitdb")|g' /opt/exploitdb/.searchsploit_rc > ~/.searchsploit_rc
ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

clear && echo "Installing Shellter (Community Edition)"
cd /opt/
wget $URL_SHELLTER
unzip shellter.zip
rm shellter.zip
cd /opt/shellter/
wget $URL_SHELLTER_README
bash -c "echo -e '#\!/bin/bash\n(cd /opt/shellter && wine shellter.exe)' > /usr/bin/shellter"
chmod +x /usr/bin/shellter

clear && echo "Installing Merlin"
apt-get install -y p7zip-full
mkdir /opt/merlin/
cd /opt/merlin/
wget $URL_MERLIN
7z x merlinServer*.7z -p'merlin'
rm merlinServer-Linux-x64*.7z
bash -c "echo -e '#\!/bin/bash\n(cd /opt/merlin && sudo ./merlinServer-Linux-x64 \"\$@\")' > /usr/bin/merlin"
chmod +x /usr/bin/merlin
#cert generation
#openssl req -x509 -newkey rsa:2048 -keyout /opt/merlin/data/x509/server.enc.key -out /opt/merlin/data/x509/server.crt
#openssl rsa -in /opt/merlin/data/x509/server.enc.key -out /opt/merlin/data/x509/server.key -passin pass:<PASSWORD>

clear && echo "Updating Windows Exploit Suggester"
cd /opt/windows-exploit-suggester/
python windows-exploit-suggester.py --update
bash -c "echo -e '#\!/bin/bash\n(cd /opt/windows-exploit-suggester && ./windows-exploit-suggester.py \"\$@\")' > /usr/bin/windows-exploit-suggester"
chmod +x /usr/bin/windows-exploit-suggester

clear && echo "Installing DNScan"
cd /opt/dnscan/
python -m pip install -r requirements.txt

clear && echo "Installing DeathStar"
cd /opt/deathstar/
pip3 install -r requirements.txt

clear && echo "Installing Empire"
cd /opt/empire/setup/
python -m pip install -r requirements.txt
./install.sh
bash -c "echo -e '#\!/bin/bash\n(cd /opt/empire && sudo ./empire)' > /usr/bin/empire"
chmod +x /usr/bin/empire
bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Empire\nExec=gnome-terminal --window -- empire\nIcon=/opt/empire/data/misc/apptemplateResources/icon/stormtrooper.icns\nCategories=Application;' > /usr/share/applications/empire.desktop"

clear && echo "Installing mitm6"
cd /opt/mitm6/
python -m pip install -r requirements.txt
python setup.py install

clear && echo "Installing Impacket"
cd /opt/impacket/
python -m pip install -r requirements.txt
python -m pip install .

clear && echo "Installing CrackMapExec" #must install after empire
apt-get install -y libssl-dev libffi-dev python-dev build-essential
cd /opt/crackmapexec/
python -m pip install -r requirements.txt
python -m pip install .
/root/.local/bin/pipenv install
/root/.local/bin/pipenv shell
python setup.py install

clear && echo "Installing BloodHound"
cd /opt/
wget $URL_BLOODHOUND
unzip BloodHound-linux-x64.zip
rm BloodHound*.zip
mv BloodHound-linux-x64/ bloodhound-bin/
touch /usr/share/applications/bloodhound.desktop
bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=BloodHound\nExec=\"/opt/bloodhound-bin/BloodHound\"\nIcon=/opt/bloodhound/src/img/icon.ico\nCategories=Application;' > /usr/share/applications/bloodhound.desktop"

clear && echo "Installing Neo4j (BloodHound Database)"
cd /opt/
apt-get remove -y java-common
apt-get install -y openjdk-8-jre-headless
wget --no-check-certificate -O - https://debian.neo4j.org/neotechnology.gpg.key | sudo apt-key add -
echo 'deb http://debian.neo4j.org/repo stable/' > /etc/apt/sources.list.d/neo4j.list
apt-get update
apt-get install -y neo4j
systemctl enable neo4j.service

# login in to http://localhost:7474/ neo4j:neo4j, change password

clear && echo "Installing Aclpwn" #Active Directory ACL exploitation with BloodHound
#https://github.com/fox-it/aclpwn.py
python -m pip install aclpwn

clear && echo "Installing Torghost"
cd /opt/torghost/
bash install.sh
systemctl disable tor.service

clear && echo "Installing SimplyEmail" #must be done before JackIt
cd /opt/simplyemail/
python -m pip install -r setup/req*.txt
./setup/setup.sh
bash -c "echo -e '#\!/bin/bash\n(cd /opt/simplyemail && ./SimplyEmail.py \"\$@\")' > /usr/bin/simplyemail"
chmod +x /usr/bin/simplyemail

clear && echo "Installing JackIt" #must be after SimplyEmail
cd /opt/jackit/
python -m pip install -e .
python setup.py install

clear && echo "Installing spoofcheck"
cd /opt/spoofcheck/
python -m pip install -r requirements.txt

clear && echo "Installing Camradar (docker)"
docker pull ullaakut/cameradar
#sudo docker run -t ullaakut/cameradar -h

clear && echo "Installing credmap"
cd /opt/credmap/
chmod +x credmap.py

clear && echo "Installing Google Chrome (Stable)"
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' | sudo tee /etc/apt/sources.list.d/google-chrome.list
apt-get update
apt-get -y install google-chrome-stable

clear && echo "Installing gowitness"
cd /opt/
mkdir gowitness
cd /opt/gowitness
wget $URL_GOWITNESS
chmod +x gowitness-linux-amd64

clear && echo "Installing ruler"
cd /opt/
mkdir /opt/ruler
cd /opt/ruler
wget $URL_RULER
chmod +x ruler-linux64

clear && echo "Installing SilentTrinity"
apt-get install -y python3.7 python3.7-dev
cd /opt/silenttrinity
wget 'https://user-images.githubusercontent.com/5151193/45964397-e462e280-bfe2-11e8-88a7-69212e0f0355.png' -O logo.png
cd Server
python3.7 -m pip install -r requirements.txt
python3.7 -m pip install markupsafe
bash -c "echo -e '#\!/bin/bash\n(cd /opt/silenttrinity/Server && sudo python3.7 st.py)' > /usr/bin/silenttrinity"
chmod +x /usr/bin/silenttrinity
bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=SilentTrinity\nExec=gnome-terminal --window -- silenttrinity\nIcon=/opt/silenttrinity/logo.png\nCategories=Application;' > /usr/share/applications/silenttrinity.desktop"

########## ---------- ##########
# Generic
########## ---------- ##########
clear && echo "Installing DBeaver"
cd /opt/
wget $URL_DBEAVER
apt-get install ./dbeaver*.deb
rm dbeaver*.deb

clear && echo "Installing nullinux"
cd /opt/nullinux
chmod +x setup.sh
./setup.sh

clear && echo "Installing enumdb"
cd /opt/enumdb
chmod +x setup.sh
./setup.sh

clear && echo "Installing File Cracks"
apt-get install -y fcrackzip

########## ---------- ##########
# VoIP
########## ---------- ##########

clear && echo "Installing sippts"
cpan -i IO:Socket:Timeout NetAddr:IP String:HexConvert Net:Pcap Net::Address::IP::Local DBI DBD::SQLite
bash -c "echo -e '#\!/bin/bash\n(cd /opt/sippts/ && perl sipscan.pl \"\$@\")' > /usr/bin/sipscan"
bash -c "echo -e '#\!/bin/bash\n(cd /opt/sippts/ && perl sipexten.pl \"\$@\")' > /usr/bin/sipexten"
bash -c "echo -e '#\!/bin/bash\n(cd /opt/sippts/ && perl sipcrack.pl \"\$@\")' > /usr/bin/sipcrack"
bash -c "echo -e '#\!/bin/bash\n(cd /opt/sippts/ && perl sipinvite.pl \"\$@\")' > /usr/bin/sipinvite"
bash -c "echo -e '#\!/bin/bash\n(cd /opt/sippts/ && perl sipsniff.pl \"\$@\")' > /usr/bin/sipsniff"
bash -c "echo -e '#\!/bin/bash\n(cd /opt/sippts/ && perl sipspy.pl \"\$@\")' > /usr/bin/sipspy"
bash -c "echo -e '#\!/bin/bash\n(cd /opt/sippts/ && perl sipdigestleak.pl \"\$@\")' > /usr/bin/sipdigestleak"
bash -c "echo -e '#\!/bin/bash\n(cd /opt/sippts/ && perl sipreport.pl \"\$@\")' > /usr/bin/sipreport"
chmod +x /usr/bin/sip*

########## ---------- ##########
# Wireless
########## ---------- ##########

clear && echo "Installing aircrack and mdk3"
apt-get install -y aircrack-ng mdk3

clear && echo "Updating OUI Database"
airodump-ng-oui-update

clear && echo "Installing coWPAtty"
apt-get install -y libpcap-dev
cd /opt/
wget $URL_COWPATTY
tar xvzf cowpatty-*.tgz
rm -r cowpatty-*.tgz
cd cowpatty*
make
make install
cd /opt/
rm -r cowpatty-*

clear && echo "Installing Fluxion"
printf "\nPress CTRL+C once Fluxion has finished installing its own dependencies.\n\n"
read -p "Press Enter to continue." </dev/tty
cd /opt/fluxion/
./fluxion.sh -i
wget 'https://raw.githubusercontent.com/FluxionNetwork/fluxion/master/logos/logo.jpg' -O logo.jpg
bash -c "echo -e '#\!/bin/bash\n(cd /opt/fluxion && ./fluxion.sh)' > /usr/bin/fluxion"
chmod +x /usr/bin/fluxion
bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Fluxion\nExec=gnome-terminal --window -- sudo fluxion\nIcon=/opt/fluxion/logo.jpg\nCategories=Application;' > /usr/share/applications/fluxion.desktop"

clear && echo "Installing hashcat"
cd /opt/
wget $URL_HASHCAT
7zr x hashcat-*.7z
rm hashcat-*.7z
mv hashcat-*/ hashcat/
ln -sf /opt/hashcat/hashcat64.bin /usr/local/bin/hashcat

clear && echo "Installing hashcat-utils"
cd /opt/
wget $URL_HASHCAT_UTILS
7zr x hashcat-utils-*.7z
rm hashcat-utils-*.7z
mv hashcat-utils-*/ hashcat-utils/

########## ---------- ##########
# Web
########## ---------- ##########

clear && echo "Installing Burp Suite Community Edition"
cd /opt/
mkdir /opt/burpsuitecommunity
cd /opt/burpsuitecommunity
curl 'https://portswigger.net/burp/releases/download?product=community&type=linux' -o install.sh && chmod +x install.sh
./install.sh -dir /opt/burpsuitecommunity -overwrite -q
rm install.sh
bash -c "echo -e 'StartupWMClass=com-install4j-runtime-launcher-UnixLauncher' >> '/usr/share/applications/Burp Suite Community Edition-0.desktop'"
#burpsuite pro 2 (jar)
#sudo sed -i -e '/^assistive_technologies=/s/^/#/' /etc/java-*-openjdk/accessibility.properties

clear && echo "Installing sqlmap"
apt-get install -y sqlmap

clear && echo "Installing nikto"
apt-get install -y nikto
nikto -update

clear && echo "Installing Gobuster"
apt-get install -y gobuster
#dirbuster directory lists
cd /opt/
wget $URL_DIRBUSTER_LISTS
tar xvf DirBuster-Lists.tar.bz2
mv DirBuster-Lists dirbuster-lists
rm DirBuster-Lists.tar.bz2

########## ---------- ##########
# Network
########## ---------- ##########

clear && echo "Installing nmapAutomator"
cd /opt/nmapautomator/
chmod +x nmapAutomator.sh

clear && echo "Installing Seth"
cd /opt/seth/
python -m pip install -r req*.txt
apt-get install -y dsniff

clear && echo "Installing Wireshark"
apt-get install -y wireshark
chmod +x /usr/bin/dumpcap
#to change user permission with gui: sudo dpkg-reconfigure wireshark-common
usermod -a -G wireshark ${RUID}

clear && echo "Installing bettercap"
apt-get install -y libnetfilter-queue-dev
cd /opt/
mkdir /opt/bettercap
cd /opt/bettercap/
wget $URL_BETTERCAP
unzip bettercap_linux_amd64_*.zip
rm bettercap*.zip
wget 'https://raw.githubusercontent.com/bettercap/media/master/logo.png' -O logo.png
bash -c "echo -e '#\!/bin/bash\nprintf \"\\\n\\\n\"\nnmcli d\nprintf \"\\\n\\\n\"\nread -p \"Enter the device name: \" int\nclear && sudo /opt/bettercap/bettercap -iface \$int' > /usr/bin/bettercap"
chmod +x /usr/bin/bettercap
bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=bettercap\nExec=gnome-terminal --window -- bettercap\nIcon=/opt/bettercap/logo.png\nCategories=Application;' > /usr/share/applications/bettercap.desktop"
git clone https://github.com/bettercap/caplets
cd /opt/bettercap/caplets/
make install

clear && echo "Installing BeEF"
apt-get install -y ruby ruby-dev
cd /opt/beef/
./install
./update-geoipdb
sed -i 's/passwd: "beef"/passwd: "admin"/g' /opt/beef/config.yaml
bash -c "echo -e '#\!/bin/bash\n(cd /opt/beef && ./beef)' > /usr/bin/beef"
chmod +x /usr/bin/beef
bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=BeEF\nExec=gnome-terminal --window -- beef\nIcon=/opt/beef/extensions/admin_ui/media/images/beef.png\nCategories=Application;' > /usr/share/applications/beef.desktop"

clear && echo "Installing FUZZBUNCH"
cd /opt/
apt-get -y install wine winbind winetricks xdotool
dpkg --add-architecture i386 && apt-get update && apt-get -y install wine32
sudo -u ${RUID} -E bash -c 'WINEARCH=win32 wine wineboot'
cd $HOME/.wine/drive_c/
sudo -u ${RUID} -E bash -c "git clone https://github.com/mdiazcl/fuzzbunch-debian.git"
bash -c "echo -e 'Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\\Environment]\n\"Path\"=\"c:\\\\\windows;c:\\\\\windows\\\\\system;C:\\\\\Python26;C:\\\\\\\fuzzbunch-debian\\\\\windows\\\\\\\fuzzbunch\"' > $HOME/.wine/drive_c/system.reg"
sudo -u ${RUID} -E bash -c "wine regedit.exe /s system.reg"
sudo -u ${RUID} -E bash -c "wine start /w c:\\\fuzzbunch-debian\\\installers\\\python-2.6.msi"
sudo -u ${RUID} -E bash -c "wine start /w c:\\\fuzzbunch-debian\\\installers\\\pywin32-219.win32-py2.6.exe"
mkdir /opt/fuzzbunch
cd /opt/fuzzbunch
wget 'https://upload.wikimedia.org/wikipedia/commons/8/8d/Seal_of_the_U.S._National_Security_Agency.svg' -O logo.svg
bash -c "echo -e '#\!/bin/bash\n(cd $HOME/.wine/drive_c/fuzzbunch-debian/windows && wine cmd.exe /C python fb.py)' > /usr/bin/fuzzbunch"
chmod +x /usr/bin/fuzzbunch
bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=FUZZBUNCH\nExec=gnome-terminal --window -- fuzzbunch\nIcon=/opt/fuzzbunch/logo.svg\nCategories=Application;' > /usr/share/applications/fuzzbunch.desktop"

clear && echo "Installing PRET"
python -m pip install colorama pysnmp

clear && echo "Installing snmpwalk"
apt-get install -y snmp

#clear && echo "Installing Nessus"
#https://www.tenable.com/downloads/nessus

#apt-get install ./Nessus-8.2.2-ubuntu1110_amd64.deb
#bash -c "echo -e '#\!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Nessus\nExec=firefox https://localhost:8834\nIcon=/opt/nessus/var/nessus/www/favicon.ico\nCategories=Application;' > /usr/share/applications/nessus.desktop"
#sudo /etc/init.d/nessusd start

########## ---------- ##########
# OSINT
########## ---------- ##########

clear && echo "Installing Cr3d0v3r"
cd /opt/cr3dov3r
python3 -m pip install -r requirements.txt
bash -c "echo -e '#\!/bin/bash\n(cd /opt/cr3dov3r && python3 Cr3d0v3r.py \"\$@\")' > /usr/bin/credover"
chmod +x /usr/bin/credover

clear && echo "Installing theHarvester"
cd /opt/theharvester/
python3 -m pip install -r requirements.txt

clear && echo "Installing LinkedInt"
cd /opt/linkedint/
python -m pip install -r requirements.txt
python -m pip install thready

clear && echo "Installing pymeta"
cd /opt/pymeta
chmod +x setup.sh
./setup.sh
chmod +x pymeta.py

########## ---------- ##########
# Wireless
########## ---------- ##########

clear && echo "Installing Kismet"
apt-get install -y kismet
usermod -aG kismet ${RUID}

clear && echo "Installing crEAP"
mkdir /opt/creap
cd /opt/creap/
wget 'https://raw.githubusercontent.com/Shellntel/scripts/master/crEAP.py'
chmod +x crEAP.py
apt install -y mercurial screen
cd /opt/
hg clone 'https://bitbucket.org/secdev/scapy-com'
dpkg --ignore-depends=python-scapy -r python-scapy
cd /opt/scapy-com/
python setup.py install

clear && echo "Installing eaphammer"
cd /opt/
git clone 'https://github.com/s0lst1c3/eaphammer'
cd /opt/eaphammer/
./kali-setup

clear && echo "Installing wifite"
apt install -y wifite tshark
cd /opt/
git clone https://github.com/ZerBea/hcxdumptool
git clone https://github.com/ZerBea/hcxtools
git clone https://github.com/aanarchyy/bully
cd /opt/hcxdumptool
make
make install
cd /opt/hcxtools
make
make install
cd /opt/bully/src/
make
make install
cd /opt/
rm -r /opt/hcxdumptool
rm -r /opt/hcxtools
rm -r /opt/bully

#Sets the favourite bar
sudo -u ${RUID} DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${RUSER_UID}/bus" dconf write /org/gnome/shell/favorite-apps "['firefox.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Terminal.desktop',  'google-chrome.desktop', 'Burp Suite Community Edition-0.desktop', 'beef.desktop', 'metasploit-framework.desktop', 'empire.desktop', 'fuzzbunch.desktop', 'silenttrinity.desktop', 'bloodhound.desktop', 'bettercap.desktop', 'wireshark.desktop', 'fluxion.desktop']"

sudo systemctl disable lighttpd.service
sudo systemctl stop lighttpd.service
apt autoremove -y
cat /dev/null > ~/.bash_history && history -c

# fix vmware display
sed -i 's/Before=cloud-init-local.service/Before=cloud-init-local.service\nAfter=display-manager.service/g' /etc/systemd/system/multi-user.target.wants/open-vm-tools.service

cd /opt/
clear
echo "Done."
printf "\nAll modules stored in /opt/\n"
echo 'View Docker images via "sudo docker images"'
#echo 'Run "msfconsole" to setup initial msf database'
#echo 'Run "cme" to setup initial CrackMapExec database'
echo 'Open Empire and run `preobfuscate` to obfuscate all modules (this will take a long time)'
echo 'BeEF username and password have been set ( u:admin p:beef )'
echo 'Download Burp Suite CA Certificate from http://burp/cert'
curl -H "Content-Type: application/json" -X POST -d '{"password":"bloodhound"}' -u neo4j:neo4j http://localhost:7474/user/neo4j/password
printf "BloodHound Database username and password have been set ( u:neo4j p:bloodhound ).\n\n"
read -p "Press Enter to reboot." </dev/tty
chown -R ${RUID}:${RUID} /opt/
reboot now