#!/bin/bash

# check ubuntu
DISTRIBUTION=`grep "^ID=" /etc/os-release | cut -d\= -f2`
if [ ! $DISTRIBUTION == "ubuntu" ]; then
  echo "Nope. Only tested on Ubuntu, sorry." 1>&2
  exit 1
fi
# check sudo
if [[ $EUID -ne 0 ]]; then
  echo "Nope. Please run with sudo." 1>&2
  exit 1
fi

# static urls (that may need to be updated)
URL_MONO='http://dl.winehq.org/wine/wine-mono/4.8.3/wine-mono-4.8.3.msi'
URL_OPENCL='http://registrationcenter-download.intel.com/akdlm/irc_nas/vcp/15532/l_opencl_p_18.1.0.015.tgz'

# function to scrape latest release from github api
url_latest() {
  local json=$(curl -s $1)
  local url=$(echo "$json" | jq -r '.assets[].browser_download_url | select(contains("'$2'"))')
  echo $url
}

# get user ids
RUID=$(who | awk 'FNR == 1 {print $1}') # real username
RUSER_UID=$(id -u ${RUID}) # real user id

# prepare os
clear && echo "Updating OS"
apt-get update && apt-get upgrade -y

clear && echo "Installing apt packages"
apt-get install -y open-vm-tools open-vm-tools-desktop net-tools git tmux whois ipcalc curl python-pip python3-pip python-qt4 libcanberra-gtk-module libgconf-2-4 jq
apt-get install -y ruby-dev #ruby for beef & wpscan

clear && echo "Installing pip modules"
sudo -H pip install pipenv && sudo -H pip3 install pipenv
python -m pip install service_identity rdpy droopescan

clear && echo "Configuring TMUX"
echo 'set -g default-terminal "screen-256color"' > ~/.tmux.conf
chown -R ${RUID}:${RUID} ~/.tmux.conf

clear && echo "Installing asciinema (terminal session recorder)" # https://github.com/asciinema/asciinema/
sudo -H pip3 install asciinema

clear && echo "Installing Firewall"
apt install -y gufw
ufw disable

clear && echo "Installing FileZilla"
apt install -y filezilla

clear && echo "Installing nmap/zenmap"
apt-get install -y nmap zenmap
wget 'https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse' -O '/usr/share/nmap/scripts/vulners.nse'
git clone --depth 1 'https://github.com/scipag/vulscan' /usr/share/nmap/scripts/vulscan
wget 'http://www.computec.ch/projekte/vulscan/download/cve.csv' -O '/usr/share/nmap/scripts/vulscan/cve.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/exploitdb.csv' -O '/usr/share/nmap/scripts/vulscan/exploitdb.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/openvas.csv' -O '/usr/share/nmap/scripts/vulscan/openvas.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/osvdb.csv' -O '/usr/share/nmap/scripts/vulscan/osvdb.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/scipvuldb.csv' -O '/usr/share/nmap/scripts/vulscan/scipvuldb.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/securityfocus.csv' -O '/usr/share/nmap/scripts/vulscan/securityfocus.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/securitytracker.csv' -O '/usr/share/nmap/scripts/vulscan/securitytracker.csv'
wget 'http://www.computec.ch/projekte/vulscan/download/xforce.csv' -O '/usr/share/nmap/scripts/vulscan/xforce.csv'
nmap --script-updatedb

clear && echo "Installing snaps"
snap install powershell --classic
snap install code --classic
snap install docker
snap install remmina
snap connect remmina:avahi-observe :avahi-observe
snap connect remmina:cups-control :cups-control
snap connect remmina:mount-observe :mount-observe
snap connect remmina:password-manager-service :password-manager-service
snap install john-the-ripper

clear && echo "Cloning repositories"
cd /opt/
git clone --depth 1 'https://github.com/actuated/msf-exploit-loop'
git clone --depth 1 'https://github.com/beefproject/beef'
git clone --depth 1 'https://github.com/BishopFox/spoofcheck'
git clone --depth 1 'https://github.com/BloodHoundAD/bloodhound'
git clone --depth 1 --recursive 'https://github.com/byt3bl33d3r/crackmapexec'
#git clone --depth 1 'https://github.com/byt3bl33d3r/deathstar'
git clone --depth 1 'https://github.com/byt3bl33d3r/silenttrinity'
git clone --depth 1 'https://github.com/byt3bl33d3r/sprayingtoolkit'
git clone --depth 1 'https://github.com/commonexploits/vlan-hopping'
git clone --depth 1 'https://github.com/D4Vinci/cr3dov3r'
git clone --depth 1 'https://github.com/dafthack/mailsniper'
git clone --depth 1 'https://github.com/danielmiessler/seclists'
git clone --depth 1 'https://github.com/davidtavarez/pwndb'
git clone --depth 1 'https://github.com/dirkjanm/privexchange' #httpattack.py must be configured
git clone --depth 1 'https://github.com/drwetter/testssl.sh.git'
git clone --depth 1 'https://github.com/Ekultek/whatwaf'
#git clone --depth 1 'https://github.com/EmpireProject/empire' --branch dev
git clone --depth 1 'https://github.com/FluxionNetwork/fluxion'
git clone --depth 1 'https://github.com/fox-it/mitm6'
git clone --depth 1 'https://gitlab.com/initstring/evil-ssdp'
git clone --depth 1 'https://github.com/insecurityofthings/jackit'
git clone --depth 1 'https://github.com/jseidl/usernamer'
git clone --depth 1 'https://github.com/lanjelot/patator'
git clone --depth 1 'https://github.com/laramies/theharvester'
git clone --depth 1 'https://github.com/lightos/credmap'
git clone --depth 1 'https://github.com/m8r0wn/enumdb'
git clone --depth 1 'https://github.com/m8r0wn/nullinux'
git clone --depth 1 'https://github.com/m8r0wn/pymeta'
git clone --depth 1 --recursive 'https://github.com/mdsecresearch/lyncsniper'
git clone --depth 1 'https://github.com/mIcHyAmRaNe/okadminfinder3'
git clone --depth 1 'https://github.com/Mr-Un1k0d3r/dkmc'
git clone --depth 1 'https://github.com/Pepelux/sippts'
git clone --depth 1 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries' ghostpack #https://github.com/GhostPack
git clone --depth 1 'https://github.com/rezasp/joomscan'
git clone --depth 1 'https://github.com/rbsec/dnscan'
git clone --depth 1 'https://github.com/RUB-NDS/pret'
git clone --depth 1 'https://github.com/s0md3v/hash-buster'
git clone --depth 1 'https://github.com/s0md3v/photon'
git clone --depth 1 'https://github.com/s0md3v/xsstrike'
git clone --depth 1 'https://github.com/SimplySecurity/simplyemail'
git clone --depth 1 'https://github.com/lgandx/responder'
git clone --depth 1 'https://github.com/susmithHCK/torghost'
git clone --depth 1 'https://github.com/SySS-Research/seth'
git clone --depth 1 'https://github.com/trustedsec/unicorn'
git clone --depth 1 'https://github.com/ustayready/fireprox'
git clone --depth 1 'https://github.com/vysec/linkedint'
git clone --depth 1 'https://github.com/wantafanta/nmapautomator'

bash -c 'echo -e "#!/bin/bash\nls | xargs -I{} git -C {} pull" > update.sh'
bash -c 'echo -e "#!/bin/bash\nsudo /usr/bin/vmhgfs-fuse .host:/ /mnt/hgfs/ -o subtype=vmhgfs-fuse,allow_other\nln -sf /mnt/hgfs/*/ ~/Desktop/" > map-shares.sh'
chmod +x *.sh

#-- PRIVILEGE ESCALATION
git clone --depth 1 'https://github.com/PowerShellMafia/powersploit'
git clone --depth 1 'https://github.com/GDSSecurity/windows-exploit-suggester'
git clone --depth 1 'https://github.com/mzet-/linux-exploit-suggester'
git clone --depth 1 'https://github.com/diego-treitos/linux-smart-enumeration'

#-- SYSTEM AUDIT
#git clone --depth 1 'https://github.com/CISOfy/lynis'

#-- DESKTOP LINKS
bash -c "echo -e '[Desktop Entry]\nName=Link to LOLBAS\nType=Application\nExec=firefox https://lolbas-project.github.io/\nIcon=firefox\nTerminal=false' > /home/${RUID}/Desktop/LOLBAS.desktop"
bash -c "echo -e '[Desktop Entry]\nName=Link to GTFOBins\nType=Application\nExec=firefox https://gtfobins.github.io/\nIcon=firefox\nTerminal=false' > /home/${RUID}/Desktop/GTFOBins.desktop"
chown -R ${RUID}:${RUID} /home/${RUID}/Desktop/*.desktop

#-- BASH ALIASES
bash -c "echo -e 'alias aquatone=\"/opt/aquatone/aquatone\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias creap=\"sudo /opt/creap/crEAP.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias dirble=\"/opt/dirble/dirble\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias enumdb=\"/opt/enumdb/enumdb.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias evil-ssdp=\"/opt/evil-ssdp/evil_ssdp.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias evilginx=\"sudo evilginx\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias gowitness=\"/opt/gowitness/gowitness-linux-amd64\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias kerbrute=\"/opt/kerbrute/kerbrute_linux_amd64\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias nmapautomator=\"sudo /opt/nmapautomator/nmapAutomator.sh\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias nse=\"ls /usr/share/nmap/scripts/ | grep \"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias pymeta=\"/opt/pymeta/pymeta.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias recursebuster=\"/opt/recursebuster/recursebuster_elf\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias responder=\"sudo /opt/responder/Responder.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias ruler=\"/opt/ruler/ruler-linux64\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias termshark=\"/opt/termshark/termshark\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias torghost=\"sudo torghost\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias unicorn=\"/opt/unicorn/unicorn.py\"' >> /home/${RUID}/.bash_aliases"
bash -c "echo -e 'alias usernamer=\"/opt/usernamer/usernamer.py\"' >> /home/${RUID}/.bash_aliases"
#. ~/.bashrc

clear && echo "Installing Metasploit"
apt-get install -y postgresql
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
rm msfinstall
cd /opt/metasploit-framework/
wget 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/lib/msf/core/web_services/public/favicon.ico' -O logo.ico
bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Metasploit Framework\nExec=gnome-terminal --window -- sudo msfconsole\nIcon=/opt/metasploit-framework/logo.ico\nCategories=Application;" > /usr/share/applications/metasploit-framework.desktop'
cp /opt/metasploit-framework/embedded/framework/config/database.yml.example /opt/metasploit-framework/embedded/framework/config/database.yml
sed -i 's/^  password:.*/  password: msf/g' /opt/metasploit-framework/embedded/framework/config/database.yml
sudo -u postgres bash -c "psql -c \"CREATE USER metasploit_framework_development WITH PASSWORD 'msf';\""
sudo -u postgres bash -c "psql -c \"CREATE DATABASE metasploit_framework_development;\""
sudo -u postgres bash -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE metasploit_framework_development TO metasploit_framework_development;\""

clear && echo "Installing searchsploit"
git clone --depth 1 'https://github.com/offensive-security/exploitdb.git' /opt/exploitdb
sed 's|path_array+=(.*)|path_array+=("/opt/exploitdb")|g' /opt/exploitdb/.searchsploit_rc > ~/.searchsploit_rc
ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

clear && echo "Installing MongoDB (cve-search Database)"
sudo apt-get install -y mongodb

clear && echo "Installing Shellter (Community Edition)"
URL_SHELLTER='https://www.shellterproject.com/Downloads/Shellter/Latest/shellter.zip'
URL_SHELLTER_README='https://www.shellterproject.com/Downloads/Shellter/Readme.txt'
cd /opt/
wget $URL_SHELLTER
unzip shellter.zip
rm shellter.zip
cd /opt/shellter/
wget $URL_SHELLTER_README
bash -c 'echo -e "#!/bin/bash\n(cd /opt/shellter && wine shellter.exe \"\$@\")" > /usr/bin/shellter'
chmod +x /usr/bin/shellter

clear && echo "Installing Don't Kill My Cat (DKMC)"
cd /opt/dkmc/
bash -c 'echo -e "#!/bin/bash\n(cd /opt/dkmc/ && python dkmc.py \"\$@\")" > /usr/bin/dkmc'
chmod +x /usr/bin/dkmc

clear && echo "Installing NtdsAudit"
URL_NTDSAUDIT=$(url_latest 'https://api.github.com/repos/Dionach/NtdsAudit/releases/latest' 'NtdsAudit.exe')
mkdir /opt/ntdsaudit
cd /opt/ntdsaudit/
wget $URL_NTDSAUDIT
bash -c 'echo -e "#!/bin/bash\n(cd /opt/ntdsaudit && wine NtdsAudit.exe \"\$@\")" > /usr/bin/ntdsaudit'
chmod +x /usr/bin/ntdsaudit

clear && echo "Installing NTDSDumpEx"
URL_NTDSDUMPEX=$(url_latest 'https://api.github.com/repos/zcgonvh/NTDSDumpEx/releases/latest' 'NTDSDumpEx.zip')
cd /opt/
wget $URL_NTDSDUMPEX
unzip NTDSDumpEx.zip -d ntdsdumpex
rm NTDSDumpEx.zip
cd /opt/ntdsdumpex/
bash -c 'echo -e "#!/bin/bash\n(cd /opt/ntdsdumpex && wine NTDSDumpEx.exe \"\$@\")" > /usr/bin/ntdsdumpex'
chmod +x /usr/bin/ntdsdumpex
# on Domain Controller, run cmd as administrator
# ntdsutil "activate instance ntds" ifm "create full c:\x" quit quit

clear && echo "Installing Merlin"
URL_MERLIN=$(url_latest 'https://api.github.com/repos/Ne0nd0g/merlin/releases/latest' 'merlinServer-Linux-x64')
apt-get install -y p7zip-full
mkdir /opt/merlin
cd /opt/merlin/
wget $URL_MERLIN
7z x merlinServer*.7z -p'merlin'
rm merlinServer-Linux-x64*.7z
bash -c 'echo -e "#!/bin/bash\n(cd /opt/merlin && sudo ./merlinServer-Linux-x64 \"\$@\")" > /usr/bin/merlin'
chmod +x /usr/bin/merlin
bash -c 'echo -e "#!/bin/bash\n(openssl req -x509 -newkey rsa:2048 -keyout /opt/merlin/data/x509/server.enc.key -out /opt/merlin/data/x509/server.crt -passout pass:merlin && openssl rsa -in /opt/merlin/data/x509/server.enc.key -out /opt/merlin/data/x509/server.key -passin pass:merlin \"\$@\")" > /usr/bin/merlin-cert'
chmod +x /usr/bin/merlin-cert
wget 'https://camo.githubusercontent.com/c39b27165e5a911744220274b00b1bfcb2742408/68747470733a2f2f692e696d6775722e636f6d2f34694b7576756a2e6a7067' -O logo.jpeg
bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Merlin\nExec=gnome-terminal --window -- merlin\nIcon=/opt/merlin/logo.jpeg\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Generate Certificate\nExec=gnome-terminal --window -- merlin-cert" > /usr/share/applications/merlin.desktop'

clear && echo "Updating Windows Exploit Suggester"
cd /opt/windows-exploit-suggester/
python windows-exploit-suggester.py --update
bash -c 'echo -e "#!/bin/bash\n(cd /opt/windows-exploit-suggester && ./windows-exploit-suggester.py \"\$@\")" > /usr/bin/windows-exploit-suggester'
chmod +x /usr/bin/windows-exploit-suggester

clear && echo "Installing DNScan"
cd /opt/dnscan/
pipenv --three install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/dnscan/ && pipenv run python dnscan.py \"\$@\")" > /usr/bin/dnscan'
chmod +x /usr/bin/dnscan

#clear && echo "Installing DeathStar"
#cd /opt/deathstar/
#pipenv --three install
#bash -c 'echo -e "#!/bin/bash\n(cd /opt/deathstar/ && pipenv run python DeathStar.py \"\$@\")" > /usr/bin/deathstar'
#chmod +x /usr/bin/deathstar

#clear && echo "Installing Empire"
#printf "\nEmpire PowerShell modules will require preobfuscation. When prompted, enter \`y\` twice.\n\n"
#read -p "Press Enter to continue." </dev/tty
#cd /opt/empire/setup/
#python -m pip install -r requirements.txt
#./install.sh
#bash -c 'echo -e "#!/bin/bash\n(cd /opt/empire && sudo ./empire \"\$@\")" > /usr/bin/empire'
#chmod +x /usr/bin/empire
#bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Empire\nExec=gnome-terminal --window -- empire\nIcon=/opt/empire/data/misc/apptemplateResources/icon/stormtrooper.icns\nCategories=Application;" > /usr/share/applications/empire.desktop'
#bash -c 'echo -e "preobfuscate\nexit" > obf.rc'
#empire -r /opt/empire/setup/obf.rc
#rm obf.rc

clear && echo "Installing mitm6"
cd /opt/mitm6/
pipenv --three install
pipenv run python setup.py install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/mitm6/ && sudo pipenv run mitm6 \"\$@\")" > /usr/bin/mitm6'
chmod +x /usr/bin/mitm6

clear && echo "Installing Impacket"
URL_IMPACKET=$(url_latest 'https://api.github.com/repos/SecureAuthCorp/impacket/releases/latest' 'impacket')
cd /opt/
wget $URL_IMPACKET
tar xvf impacket*.tar.gz
rm impacket-*.tar.gz
mv impacket-*/ impacket/
cd /opt/impacket/
pip install -r requirements.txt
pip install .

clear && echo "Installing CrackMapExec"
apt-get install -y libssl-dev libffi-dev python-dev build-essential
cd /opt/crackmapexec/
pipenv --two install
pipenv run python setup.py install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/crackmapexec/ && pipenv run cme \"\$@\")" > /usr/bin/cme'
chmod +x /usr/bin/cme
bash -c 'echo -e "#!/bin/bash\n(cd /opt/crackmapexec/ && pipenv run cmedb \"\$@\")" > /usr/bin/cmedb'
chmod +x /usr/bin/cmedb

clear && echo "Installing BloodHound"
URL_BLOODHOUND=$(url_latest 'https://api.github.com/repos/BloodHoundAD/BloodHound/releases/latest' 'linux-x64')
cd /opt/
wget $URL_BLOODHOUND
unzip BloodHound-linux-x64.zip
rm BloodHound*.zip
mv BloodHound-linux-x64/ bloodhound-bin/
touch /usr/share/applications/bloodhound.desktop
bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=BloodHound\nExec=\"/opt/bloodhound-bin/BloodHound\"\nIcon=/opt/bloodhound/src/img/icon.ico\nCategories=Application;" > /usr/share/applications/bloodhound.desktop'

clear && echo "Installing Neo4j (BloodHound Database)"
cd /opt/
apt-get remove -y java-common
apt-get install -y openjdk-8-jre-headless
wget --no-check-certificate -O - https://debian.neo4j.org/neotechnology.gpg.key | sudo apt-key add -
echo 'deb http://debian.neo4j.org/repo stable/' > /etc/apt/sources.list.d/neo4j.list
apt-get update
apt-get install -y neo4j
systemctl enable neo4j.service

clear && echo "Installing Aclpwn" #Active Directory ACL exploitation with BloodHound
#https://github.com/fox-it/aclpwn.py
python -m pip install aclpwn

clear && echo "Installing Torghost"
cd /opt/torghost/
bash install.sh
systemctl disable tor.service
#firefox http://about:config
#set network.dns.blockDotOnion;false
apt install -y chrome-gnome-shell #firefox gnome extensions pre-reqs

clear && echo "Installing fireprox"
cd /opt/fireprox/
pipenv --three install -r requirements.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/fireprox && pipenv run python fire.py \"\$@\")" > /usr/bin/fireprox'
chmod +x /usr/bin/fireprox

clear && echo "Installing SimplyEmail"
sudo apt install -y python-lxml wget grep antiword odt2txt python-dev libxml2-dev libxslt1-dev
cd /opt/simplyemail/
pipenv --two install -r setup/req*.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/simplyemail && pipenv run python2.7 SimplyEmail.py \"\$@\")" > /usr/bin/simplyemail'
chmod +x /usr/bin/simplyemail

clear && echo "Installing JackIt"
cd /opt/jackit/
pipenv --two install
pipenv run python setup.py install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/jackit/ && sudo pipenv run jackit \"\$@\")" > /usr/bin/jackit'
chmod +x /usr/bin/jackit

clear && echo "Installing spoofcheck"
cd /opt/spoofcheck/
pipenv --two install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/spoofcheck/ && sudo pipenv run python spoofcheck.py \"\$@\")" > /usr/bin/spoofcheck'
chmod +x /usr/bin/spoofcheck

clear && echo "Installing Camradar (docker)"
docker pull ullaakut/cameradar
#sudo docker run -t ullaakut/cameradar -h

clear && echo "Installing credmap"
cd /opt/credmap/
chmod +x credmap.py
bash -c 'echo -e "#!/bin/bash\n(cd /opt/credmap/ && python credmap.py \"\$@\")" > /usr/bin/credmap'
chmod +x /usr/bin/credmap

clear && echo "Installing Google Chrome (Stable)" #for gowitness
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' | sudo tee /etc/apt/sources.list.d/google-chrome.list
apt-get update
apt-get -y install google-chrome-stable

clear && echo "Installing gowitness"
URL_GOWITNESS=$(url_latest 'https://api.github.com/repos/sensepost/gowitness/releases/latest' 'linux-amd64')
mkdir /opt/gowitness
cd /opt/gowitness
wget $URL_GOWITNESS
chmod +x gowitness-linux-amd64

clear && echo "Installing Chromium Browser" #for aquatone
apt-get -y install chromium-browser

clear && echo "Installing aquatone"
URL_AQUATONE=$(url_latest 'https://api.github.com/repos/michenriksen/aquatone/releases/latest' 'linux_amd64')
mkdir /opt/aquatone
cd /opt/aquatone
wget $URL_AQUATONE
unzip aquatone*.zip
rm aquatone*.zip
chmod +x aquatone

clear && echo "Installing ruler"
URL_RULER=$(url_latest 'https://api.github.com/repos/sensepost/ruler/releases/latest' 'linux64')
mkdir /opt/ruler
cd /opt/ruler/
wget $URL_RULER
chmod +x ruler-linux64

clear && echo "Installing SilentTrinity"
apt-get install -y python3.7 python3.7-dev
cd /opt/silenttrinity/
wget 'https://user-images.githubusercontent.com/5151193/45964397-e462e280-bfe2-11e8-88a7-69212e0f0355.png' -O logo.png
cd Server
pipenv --three install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/silenttrinity/Server && sudo pipenv run python3.7 st.py \"\$@\")" > /usr/bin/silenttrinity'
chmod +x /usr/bin/silenttrinity
bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=SilentTrinity\nExec=gnome-terminal --window -- silenttrinity\nIcon=/opt/silenttrinity/logo.png\nCategories=Application;" > /usr/share/applications/silenttrinity.desktop'

clear && echo "Installing SprayingToolkit"
cd /opt/sprayingtoolkit/
pipenv --three install -r requirements.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sprayingtoolkit/ && sudo pipenv run python3.7 aerosol.py \"\$@\")" > /usr/bin/aerosol'
chmod +x /usr/bin/aerosol
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sprayingtoolkit/ && sudo pipenv run python3.7 atomizer.py \"\$@\")" > /usr/bin/atomizer'
chmod +x /usr/bin/atomizer
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sprayingtoolkit/ && sudo pipenv run python3.7 spindrift.py \"\$@\")" > /usr/bin/spindrift'
chmod +x /usr/bin/spindrift
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sprayingtoolkit/ && sudo pipenv run python3.7 vaporizer.py \"\$@\")" > /usr/bin/vaporizer'
chmod +x /usr/bin/vaporizer

########## ---------- ##########
# Generic
########## ---------- ##########

clear && echo "Installing DBeaver"
URL_DBEAVER='https://dbeaver.io/files/dbeaver-ce_latest_amd64.deb'
cd /opt/
wget $URL_DBEAVER
apt-get install ./dbeaver*.deb
rm dbeaver*.deb

clear && echo "Installing Sqlectron"
URL_SQLECTRON=$(url_latest 'https://api.github.com/repos/sqlectron/sqlectron-gui/releases/latest' 'amd64')
cd /opt/
wget $URL_SQLECTRON
apt install ./Sqlectron*.deb
rm Sqlectron*.deb

clear && echo "Installing nullinux"
cd /opt/nullinux/
apt-get install -y smbclient
pipenv --three install -r requirements.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/nullinux && pipenv run python nullinux.py \"\$@\")" > /usr/bin/nullinux'
chmod +x /usr/bin/nullinux

clear && echo "Installing enumdb"
cd /opt/enumdb/
chmod +x setup.sh
./setup.sh

clear && echo "Installing File Cracks"
apt-get install -y fcrackzip

clear && echo "Installing NFS Utils"
apt-get install -y nfs-common

clear && echo "Installing GPS Utils"
apt-get install -y gpsd gpsd-clients

########## ---------- ##########
# Brute-force
########## ---------- ##########

clear && echo "Installing patator"
cd /opt/patator/
apt install -y libcurl4-openssl-dev python3-dev libssl-dev # pycurl
apt install -y ldap-utils # ldapsearch
apt install -y libmysqlclient-dev # mysqlclient-python
apt install -y ike-scan unzip default-jdk
apt install -y libsqlite3-dev libsqlcipher-dev # pysqlcipher
pipenv --two install -r requirements.txt
pipenv run python setup.py install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/patator/ && sudo pipenv run patator.py \"\$@\")" > /usr/bin/patator'
chmod +x /usr/bin/patator

clear && echo "Installing kerbrute"
URL_KERBRUTE=$(url_latest 'https://api.github.com/repos/ropnop/kerbrute/releases/latest' 'linux_amd64')
mkdir /opt/kerbrute
cd /opt/kerbrute
wget $URL_KERBRUTE
chmod +x kerbrute_linux_amd64

########## ---------- ##########
# VoIP
########## ---------- ##########

clear && echo "Installing sippts"
cpan -i IO:Socket:Timeout NetAddr:IP String:HexConvert Net:Pcap Net::Address::IP::Local DBI DBD::SQLite
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipscan.pl \"\$@\")" > /usr/bin/sipscan'
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipexten.pl \"\$@\")" > /usr/bin/sipexten'
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipcrack.pl \"\$@\")" > /usr/bin/sipcrack'
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipinvite.pl \"\$@\")" > /usr/bin/sipinvite'
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipsniff.pl \"\$@\")" > /usr/bin/sipsniff'
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipspy.pl \"\$@\")" > /usr/bin/sipspy'
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipdigestleak.pl \"\$@\")" > /usr/bin/sipdigestleak'
bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipreport.pl \"\$@\")" > /usr/bin/sipreport'
chmod +x /usr/bin/sip*

########## ---------- ##########
# Wireless
########## ---------- ##########

clear && echo "Installing aircrack and mdk3"
apt-get install -y aircrack-ng mdk3

clear && echo "Updating OUI Database"
airodump-ng-oui-update

clear && echo "Installing coWPAtty"
URL_COWPATTY='http://www.willhackforsushi.com/code/cowpatty/4.6/cowpatty-4.6.tgz'
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
bash -c 'echo -e "#!/bin/bash\n(cd /opt/fluxion && ./fluxion.sh \"\$@\")" > /usr/bin/fluxion'
chmod +x /usr/bin/fluxion
bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Fluxion\nExec=gnome-terminal --window -- sudo fluxion\nIcon=/opt/fluxion/logo.jpg\nCategories=Application;" > /usr/share/applications/fluxion.desktop'

clear && echo "Installing hashcat"
URL_HASHCAT=$(url_latest 'https://api.github.com/repos/hashcat/hashcat/releases/latest' 'hashcat')
cd /opt/
wget $URL_HASHCAT
7zr x hashcat-*.7z
rm hashcat-*.7z
mv hashcat-*/ hashcat/
ln -sf /opt/hashcat/hashcat64.bin /usr/local/bin/hashcat
# allows hashcat to work using cpu
# https://software.intel.com/en-us/articles/opencl-drivers#latest_CPU_runtime
cd /opt/
wget $URL_OPENCL
tar xvzf l_opencl_*.tgz
rm -r l_opencl_*.tgz
cd l_opencl_*
sudo apt install -y lsb-core
echo -e "ACCEPT_EULA=accept\nCONTINUE_WITH_OPTIONAL_ERROR=yes\nPSET_INSTALL_DIR=/opt/intel\nCONTINUE_WITH_INSTALLDIR_OVERWRITE=yes\nPSET_MODE=install\nINTEL_SW_IMPROVEMENT_PROGRAM_CONSENT=no\nCOMPONENTS=;intel-openclrt__x86_64;intel-openclrt-pset" > settings.cfg
sudo bash install.sh --silent settings.cfg
cd /opt/
rm -r l_opencl_*

clear && echo "Installing hashcat-utils"
URL_HASHCAT_UTILS=$(url_latest 'https://api.github.com/repos/hashcat/hashcat-utils/releases/latest' 'hashcat-utils')
cd /opt/
wget $URL_HASHCAT_UTILS
7zr x hashcat-utils-*.7z
rm hashcat-utils-*.7z
mv hashcat-utils-*/ hashcat-utils/

clear && echo "Installing NTLMv1 Multitool"
cd /opt/
git clone --depth 1 'https://github.com/evilmog/ntlmv1-multi'

########## ---------- ##########
# Web
########## ---------- ##########

# burp suite community or pro
cd /opt/
if [ ! -f burpsuite_pro_linux*.sh ] #burp professional installation script not found - ask if required
then
  clear
  printf "Burp Suite Professional installation script not found.\n\nDownload \`burpsuite_pro_linux_v2_1.sh\` from: https://portswigger.net/users/youraccount \n\n"
  read -p "Save this to /opt/*.sh if Pro is required.\n\nPress Enter to continue (or skip)." </dev/tty
  if [ ! -f burpsuite_pro_linux*.sh ] #burp professional not required, install burp community edition
  then
    clear && echo "Installing Burp Suite Community Edition"
    curl 'https://portswigger.net/burp/releases/download?product=community&type=linux' -o install.sh && chmod +x install.sh
    ./install.sh -dir /opt/burpsuitecommunity -overwrite -q
    rm install.sh
    bash -c "echo -e 'StartupWMClass=com-install4j-runtime-launcher-UnixLauncher' >> '/usr/share/applications/Burp Suite Community Edition-0.desktop'"
  fi
fi
if [ -f burpsuite_pro_linux*.sh ] #burp professional installation script found, install burp professional
then
  clear && echo "Installing Burp Suite Professional Edition"
  bash burpsuite_pro_linux*.sh -dir /opt/burpsuitepro -overwrite -q
  rm burpsuite_pro_linux*.sh
  bash -c "echo -e 'StartupWMClass=com-install4j-runtime-launcher-UnixLauncher' >> '/usr/share/applications/Burp Suite Professional-0.desktop'"
fi
# download jython (burp extensions)
cd /home/${RUID}/Documents/
wget 'http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.0/jython-standalone-2.7.0.jar' -O jython-standalone-2.7.0.jar

clear && echo "Installing sqlmap"
apt-get install -y sqlmap

clear && echo "Installing Whatwaf"
cd /opt/whatwaf/
pipenv --three install -r requirements.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/whatwaf && pipenv run python whatwaf.py \"\$@\")" > /usr/bin/whatwaf'
chmod +x /usr/bin/whatwaf

clear && echo "Installing nikto"
apt-get install -y nikto
nikto -update

clear && echo "Installing testssl.sh"
bash -c 'echo -e "#!/bin/bash\n(/opt/testssl.sh/testssl.sh \"\$@\")" > /usr/bin/testssl.sh'
chmod +x /usr/bin/testssl.sh

clear && echo "Installing Gobuster"
apt-get install -y gobuster
#dirbuster directory lists
URL_DIRBUSTER_LISTS='https://netix.dl.sourceforge.net/project/dirbuster/DirBuster%20Lists/Current/DirBuster-Lists.tar.bz2'
cd /opt/
wget $URL_DIRBUSTER_LISTS
tar xvf DirBuster-Lists.tar.bz2
mv DirBuster-Lists dirbuster-lists
rm DirBuster-Lists.tar.bz2

clear && echo "Installing dirble"
URL_DIRBLE=$(url_latest 'https://api.github.com/repos/nccgroup/dirble/releases/latest' 'x86_64-linux')
cd /opt/
wget $URL_DIRBLE
unzip dirble*.zip
rm dirble*.zip

clear && echo "Installing recursebuster"
URL_RECURSEBUSTER=$(url_latest 'https://api.github.com/repos/C-Sto/recursebuster/releases/latest' 'recursebuster_elf')
URL_RECURSEBUSTER_README='https://raw.githubusercontent.com/C-Sto/recursebuster/master/README.md'
mkdir /opt/recursebuster
cd /opt/recursebuster/
wget $URL_RECURSEBUSTER
wget $URL_RECURSEBUSTER_README
chmod +x recursebuster_elf

clear && echo "Installing okadminfinder3"
cd /opt/okadminfinder3/
pipenv --three install -r requirements.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/okadminfinder3 && pipenv run python okadminfinder.py \"\$@\")" > /usr/bin/okadminfinder3'
chmod +x /usr/bin/okadminfinder3

clear && echo "Installing XSStrike"
cd /opt/xsstrike/
pipenv --three install -r requirements.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/xsstrike && pipenv run python xsstrike.py \"\$@\")" > /usr/bin/xsstrike'
chmod +x /usr/bin/xsstrike
URL_GECKODRIVER=$(url_latest 'https://api.github.com/repos/mozilla/geckodriver/releases/latest' 'linux64')
curl -s -L "$URL_GECKODRIVER" | tar -xz
chmod +x geckodriver
sudo mv geckodriver '/usr/local/bin'

clear && echo "Installing WPScan"
sudo gem install wpscan
wpscan --update

clear && echo "Installing joomscan"
bash -c 'echo -e "#!/bin/bash\n(/opt/joomscan/joomscan.pl \"\$@\")" > /usr/bin/joomscan'
chmod +x /usr/bin/joomscan

clear && echo "Installing ODAT: Oracle Database Attacking Tool"
URL_ODAT=$(url_latest 'https://api.github.com/repos/quentinhardy/odat/releases/latest' 'x86_64')
cd /opt/
wget $URL_ODAT
tar xvf odat*.tar.gz
rm odat*.tar.gz
mv odat*/ odat/
ln -sf /opt/odat/odat* /usr/local/bin/odat

########## ---------- ##########
# Webshell
########## ---------- ##########

#cd /opt
#php
#https://github.com/mIcHyAmRaNe/wso-webshell
#https://github.com/flozz/p0wny-shell

########## ---------- ##########
# Network
########## ---------- ##########

clear && echo "Installing nmapAutomator"
cd /opt/nmapautomator/
chmod +x nmapAutomator.sh
#sslscan, gobuster, nikto, joomscan, wpscan, droopescan, smbmap, smbclient, enum4linux, snmp-check, snmpwalk, dnsrecon, odat.py, 

clear && echo "Installing Seth"
cd /opt/seth/
pipenv --two install
apt-get install -y dsniff
bash -c 'echo -e "#!/bin/bash\n(cd /opt/seth/ && sudo pipenv run ./seth.sh \"\$@\")" > /usr/bin/seth'
chmod +x /usr/bin/seth

clear && echo "Installing Wireshark"
apt-get install -y wireshark
chmod +x /usr/bin/dumpcap
#to change user permission with gui: sudo dpkg-reconfigure wireshark-common
usermod -a -G wireshark ${RUID}

clear && echo "Installing termshark"
URL_TERMSHARK=$(url_latest 'https://api.github.com/repos/gcla/termshark/releases/latest' 'linux_x64')
cd /opt/
wget $URL_TERMSHARK
tar xvf termshark*.tar.gz
rm termshark*.tar.gz
mv termshark_*/ termshark/

clear && echo "Installing bettercap"
URL_BETTERCAP=$(url_latest 'https://api.github.com/repos/bettercap/bettercap/releases/latest' 'linux_amd64')
apt-get install -y libnetfilter-queue-dev
mkdir /opt/bettercap
cd /opt/bettercap/
wget $URL_BETTERCAP
unzip bettercap_linux_amd64_*.zip
rm bettercap*.zip
wget 'https://raw.githubusercontent.com/bettercap/media/master/logo.png' -O logo.png
./bettercap -eval "caplets.update; ui.update; q"
sed -i 's/^set api.rest.username.*/set api.rest.username admin/g' /usr/local/share/bettercap/caplets/http-ui.cap
sed -i 's/^set api.rest.password.*/set api.rest.password bettercap/g' /usr/local/share/bettercap/caplets/http-ui.cap
bash -c 'echo -e "#!/bin/bash\n(sudo /opt/bettercap/bettercap \"\$@\")" > /usr/bin/bettercap'
chmod +x /usr/bin/bettercap
bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=bettercap\nExec=gnome-terminal --window -- bash -c '\''printf \"\\\n\\\n\" && nmcli d && printf \"\\\n\\\n\" && read -p \"Enter the device name: \" int && clear && sudo /opt/bettercap/bettercap -iface \$int -caplet http-ui'\''\nIcon=/opt/bettercap/logo.png\nCategories=Application;" > /usr/share/applications/bettercap.desktop'

clear && echo "Installing BeEF"
apt-get install -y ruby ruby-dev
cd /opt/beef/
./install
./update-geoipdb
sed -i 's/passwd: "beef"/passwd: "admin"/g' /opt/beef/config.yaml
bash -c 'echo -e "#!/bin/bash\n(cd /opt/beef && ./beef \"\$@\")" > /usr/bin/beef'
chmod +x /usr/bin/beef
bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=BeEF\nExec=gnome-terminal --window -- beef\nIcon=/opt/beef/extensions/admin_ui/media/images/beef.png\nCategories=Application;" > /usr/share/applications/beef.desktop'

clear && echo "Installing wine"
apt-get -y install wine winbind winetricks xdotool
dpkg --add-architecture i386 && apt-get update && apt-get -y install wine32
sudo -u ${RUID} -E bash -c 'WINEARCH=win32 wine wineboot'

clear && echo "Installing FUZZBUNCH"
cd $HOME/.wine/drive_c/
sudo -u ${RUID} -E bash -c "git clone --depth 1 https://github.com/mdiazcl/fuzzbunch-debian.git"
bash -c "echo -e 'Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\\Environment]\n\"Path\"=\"c:\\\\\windows;c:\\\\\windows\\\\\system;C:\\\\\Python26;C:\\\\\\\fuzzbunch-debian\\\\\windows\\\\\\\fuzzbunch\"' > $HOME/.wine/drive_c/system.reg"
sudo -u ${RUID} -E bash -c "wine regedit.exe /s system.reg"
sudo -u ${RUID} -E bash -c "wine start /w c:\\\fuzzbunch-debian\\\installers\\\python-2.6.msi"
sudo -u ${RUID} -E bash -c "wine start /w c:\\\fuzzbunch-debian\\\installers\\\pywin32-219.win32-py2.6.exe"
mkdir /opt/fuzzbunch
cd /opt/fuzzbunch/
wget 'https://upload.wikimedia.org/wikipedia/commons/8/8d/Seal_of_the_U.S._National_Security_Agency.svg' -O logo.svg
bash -c 'echo -e "#!/bin/bash\n(cd $HOME/.wine/drive_c/fuzzbunch-debian/windows && wine cmd.exe /C python fb.py \"\$@\")" > /usr/bin/fuzzbunch'
chmod +x /usr/bin/fuzzbunch
bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=FUZZBUNCH\nExec=gnome-terminal --window -- fuzzbunch\nIcon=/opt/fuzzbunch/logo.svg\nCategories=Application;" > /usr/share/applications/fuzzbunch.desktop'

clear && echo "Installing EvilClippy"
URL_EVILCLIPPY=$(url_latest 'https://api.github.com/repos/outflanknl/EvilClippy/releases/latest' 'EvilClippy.exe')
URL_EVILCLIPPY_MCDF=$(url_latest 'https://api.github.com/repos/outflanknl/EvilClippy/releases/latest' 'OpenMcdf.dll')
URL_EVILCLIPPY_README='https://raw.githubusercontent.com/outflanknl/EvilClippy/master/README.md'
mkdir /opt/evilclippy
cd /opt/evilclippy/
wget $URL_EVILCLIPPY
wget $URL_EVILCLIPPY_MCDF
wget $URL_EVILCLIPPY_README
bash -c 'echo -e "#!/bin/bash\n(cd /opt/evilclippy/ && wine EvilClippy.exe \"\$@\")" > /usr/bin/evilclippy'
chmod +x /usr/bin/evilclippy
mkdir /usr/share/wine/mono
wget $URL_MONO -o '/usr/share/wine/mono/wine-mono.msi'
sudo -u ${RUID} -E bash -c "wine msiexec /i /usr/share/wine/mono/wine-mono.msi"

clear && echo "Installing PRET"
cd /opt/pret/
pipenv --two install colorama pysnmp
bash -c 'echo -e "#!/bin/bash\n(cd /opt/pret/ && pipenv run python pret.py \"\$@\")" > /usr/bin/pret'
chmod +x /usr/bin/pret

clear && echo "Installing snmpwalk"
apt-get install -y snmp

clear && echo "Installing nbtscan"
apt-get install -y nbtscan

#clear && echo "Installing Nessus"
cd /opt/
while [ ! -f Nessus*.deb ]
do
  clear
  printf "Nessus installation file not found.\n\nDownload Nessus package from: https://www.tenable.com/downloads/nessus ( \`ubuntu & amd64\` )\n\n"
  read -p "Save it to /opt/Nessus-####.deb, then press Enter to continue." </dev/tty
done
if [ -f Nessus*.deb ]
then
  clear && echo "Installing Nessus"
  apt-get install ./Nessus-*.deb
  bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Nessus\nExec=firefox https://localhost:8834\nIcon=/opt/nessus/var/nessus/www/favicon.ico\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Update\nExec=gnome-terminal --window -- bash -c '\''sudo /opt/nessus/sbin/nessuscli update --all && read -p \"Press Enter to close.\" </dev/tty'\''" > /usr/share/applications/nessus.desktop'
  sudo /etc/init.d/nessusd start
fi
rm Nessus*.deb

clear && echo "Installing frogger2"
apt-get install -y yersinia vlan arp-scan
chmod +x /opt/vlan-hopping/frogger2.sh

#clear && echo "Installing Elasticsearch 6.x (natlas Database)"
#wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
#echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
#apt-get update
#apt-get install -y apt-transport-https elasticsearch
#sudo systemctl daemon-reload
#sudo systemctl enable elasticsearch.service
#sudo systemctl start elasticsearch.service

#clear && echo "Installing natlas"
#URL_NATLAS_AGENT=$(url_latest 'https://api.github.com/repos/natlas/natlas/releases/latest' 'natlas-agent')
#URL_NATLAS_SERVER=$(url_latest 'https://api.github.com/repos/natlas/natlas/releases/latest' 'natlas-server')
#mkdir /opt/natlas
#cd /opt/natlas/
#wget $URL_NATLAS_AGENT
#wget $URL_NATLAS_SERVER
#tar xvzf natlas-server*.tgz
#tar xvzf natlas-agent*.tgz
#rm -r natlas-*.tgz
#cd /opt/natlas/natlas-server/
#./setup-server.sh

#sudo cp /opt/natlas/natlas-server/deployment/natlas-server.service /etc/systemd/system/natlas-server.service
#sudo systemctl daemon-reload
#sudo systemctl enable natlas-server.service
#sudo systemctl start natlas-server.service

#bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Natlas\nExec=firefox http://localhost:5000\nIcon=/opt/natlas/natlas-server/app/static/img/natlas-logo.png\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Add User\nExec=gnome-terminal --window -- bash -c '\''printf \"\\\n\\\n\" && read -p \"Enter valid email address: \" email && clear && cd /opt/natlas/natlas-server/ && source venv/bin/activate && ./add-user.py --admin \$email && printf \"\\\n\\\n\" && read -p \"Press Enter to close.\" </dev/tty'\''" > /usr/share/applications/natlas.desktop'

#cd /opt/natlas/natlas-agent/
#./setup-agent.sh

#sudo cp /opt/natlas/natlas-agent/deployment/natlas-agent.service /etc/systemd/system/natlas-agent.service
#sudo systemctl daemon-reload
#sudo systemctl start natlas-agent

#chmod -R 777 /opt/natlas/

########## ---------- ##########
# OSINT
########## ---------- ##########

clear && echo "Installing Cr3d0v3r"
cd /opt/cr3dov3r/
pipenv --three install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/cr3dov3r && pipenv run python Cr3d0v3r.py \"\$@\")" > /usr/bin/credover'
chmod +x /usr/bin/credover

clear && echo "Installing Hash-Buster"
cd /opt/hash-buster/
sudo make install

clear && echo "Installing LinkedInt"
cd /opt/linkedint/
pipenv --two install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/linkedint && pipenv run python LinkedInt.py \"\$@\")" > /usr/bin/linkedint'
chmod +x /usr/bin/linkedint

clear && echo "Installing pwndb"
cd /opt/pwndb/
pipenv --three install -r requirements.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/pwndb && pipenv run python pwndb.py \"\$@\")" > /usr/bin/pwndb'
chmod +x /usr/bin/pwndb

clear && echo "Installing pymeta"
cd /opt/pymeta/
chmod +x setup.sh
./setup.sh
chmod +x pymeta.py

clear && echo "Installing theHarvester"
cd /opt/theharvester/
pipenv --three install
bash -c 'echo -e "#!/bin/bash\n(cd /opt/theharvester && pipenv run python theHarvester.py \"\$@\")" > /usr/bin/theharvester'
chmod +x /usr/bin/theharvester

clear && echo "Installing Photon"
cd /opt/photon/
pipenv --three install -r requirements.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/photon && pipenv run python photon.py \"\$@\")" > /usr/bin/photon'
chmod +x /usr/bin/photon

########## ---------- ##########
# Phishing
########## ---------- ##########

clear && echo "Installing evilginx"
URL_EVILGINX=$(url_latest 'https://api.github.com/repos/kgretzky/evilginx2/releases/latest' 'linux_x86')
mkdir /opt/evilginx
cd /opt/evilginx/
wget $URL_EVILGINX
unzip *.zip
rm *.zip
bash install.sh
chmod +x /usr/local/bin/evilginx

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
git clone --depth 1 'https://github.com/s0lst1c3/eaphammer'
cd /opt/eaphammer/
./kali-setup
pipenv --three install -r pip.req
bash -c 'echo -e "#!/bin/bash\n(cd /opt/eaphammer/ && sudo pipenv run python eaphammer \"\$@\")" > /usr/bin/eaphammer'
chmod +x /usr/bin/eaphammer

clear && echo "Installing wifite"
apt install -y wifite tshark

clear && echo "Installing hcxtools" # part wifite reqs.
cd /opt/
git clone --depth 1 'https://github.com/ZerBea/hcxtools'
cd /opt/hcxtools/
make
make install

clear && echo "Installing hcxdumptool" # part wifite reqs.
cd /opt/
git clone --depth 1 'https://github.com/ZerBea/hcxdumptool'
cd /opt/hcxdumptool/
make
make install

clear && echo "Installing bully" # part wifite reqs.
cd /opt/
git clone --depth 1 'https://github.com/aanarchyy/bully'
cd /opt/bully/src/
make
make install

########## ---------- ##########
# Misc
########## ---------- ##########

clear && echo "Installing proxmark3"
cd /opt/
git clone --depth 1 'https://github.com/Proxmark/proxmark3'
cd /opt/proxmark3/
sudo apt install -y 7zip build-essential libreadline5 libreadline-dev libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi libstdc++-arm-none-eabi-newlib libpcsclite-dev pcscd
sudo cp -rf driver/77-mm-usb-device-blacklist.rules /etc/udev/rules.d/77-mm-usb-device-blacklist.rules
sudo udevadm control --reload-rules
sudo adduser ${RUID} dialout
make clean && make all
#cd /opt/proxmark3/client/ && ./proxmark3 /dev/ttyACM0

clear && echo "Installing Go"
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt-get update
sudo apt-get install -y golang-go

# moved to end of script due to time of populating the database
clear && echo "Installing cve-search"
git clone --depth 1 'https://github.com/cve-search/cve-search' /opt/cve-search
cd /opt/cve-search/
pipenv --three install -r requirements.txt
bash -c 'echo -e "#!/bin/bash\n(cd /opt/cve-search/ && sudo pipenv run python ./bin/search.py \"\$@\")" > /usr/bin/cve-search'
bash -c 'echo -e "#!/bin/bash\n(cd /opt/cve-search/ && sudo pipenv run python ./web/index.py \"\$@\")" > /usr/bin/cve-search-webui'
chmod +x /usr/bin/cve-search*

clear && read -r -p "Populating the cve database will take a good few hours. Do you want to do this now? [y/N] " response
response=${response,,} # convert to lower case
if [[ "$response" =~ ^(yes|y)$ ]]
then
  clear && echo "Ok... Populating the cve-search database now..."
  pipenv run python ./sbin/db_mgmt_json.py -p
  pipenv run python ./sbin/db_mgmt_cpe_dictionary.py
  pipenv run python ./sbin/db_updater.py -c
else
  clear && echo "Nevermind. A script has been created in /opt/ for you to run later."
  bash -c 'echo -e "#!/bin/bash\ncd /opt/cve-search/\nsudo pipenv run python ./sbin/db_mgmt_json.py -p\nsudo pipenv run python ./sbin/db_mgmt_cpe_dictionary.py\nsudo pipenv run python ./sbin/db_updater.py -c" > /opt/cve-populate.sh'
  chmod +x /opt/*.sh
fi
bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=cve-search\nExec=firefox http://127.0.0.1:5000\nIcon=/opt/cve-search/web/static/img/favicon.ico\nCategories=Application;" > /usr/share/applications/cve-search.desktop'

########## ---------- ##########
# End
########## ---------- ##########

# Reset the Dock favourites
sudo -u ${RUID} DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${RUSER_UID}/bus" dconf write /org/gnome/shell/favorite-apps "['firefox.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Terminal.desktop',  'google-chrome.desktop', 'nessus.desktop', 'Burp Suite Community Edition-0.desktop', 'beef.desktop', 'metasploit-framework.desktop', 'silenttrinity.desktop', 'merlin.desktop', 'fuzzbunch.desktop', 'bloodhound.desktop', 'bettercap.desktop', 'wireshark.desktop', 'fluxion.desktop']"

# Services fixes
sudo systemctl disable apache2.service
sudo systemctl stop apache2.service
sudo systemctl disable lighttpd.service
sudo systemctl stop lighttpd.service

# Cleanup apt
apt autoremove -y

# fix vmware display
sed -i 's/Before=cloud-init-local.service/Before=cloud-init-local.service\nAfter=display-manager.service/g' /lib/systemd/system/open-vm-tools.service

# Clear terminal history
cat /dev/null > /home/${RUID}/.bash_history && history -c
chown -R ${RUID}:${RUID} /home/${RUID}/.bash_history

# Set permissions in /opt/
chown -R ${RUID}:${RUID} /opt/
#chmod -R 777 /opt/natlas/

clear && echo "Done."
printf "\nAll modules stored in /opt/\n"
#echo 'View Docker images via "sudo docker images"'
#echo 'Run "msfconsole" to setup initial msf database'
#echo 'Run "cme" to setup initial CrackMapExec database'
printf " \nNotes:"
echo 'Download Burp Suite CA Certificate from http://burp/cert/'
echo 'To resolve .onion addresses (via torghost) in firefox open \`about:config\` and set \`network.dns.blockDotOnion\` to \`false\`'
printf " \nCreds:"
echo 'BeEF username and password have been set ( u:admin p:beef )'
echo 'bettercap UI username and password have been set ( u:admin p:bettercap )'
# Set neo4j database password to \`bloodhound\`
curl -H "Content-Type: application/json" -X POST -d '{"password":"bloodhound"}' -u neo4j:neo4j http://localhost:7474/user/neo4j/password
printf "BloodHound Database username and password have been set ( u:neo4j p:bloodhound ).\n\n"
read -p "Press Enter to reboot." </dev/tty

# Clear terminal history
cat /dev/null > /home/${RUID}/.bash_history && history -c
chown -R ${RUID}:${RUID} /home/${RUID}/.bash_history

# Reboot
reboot now