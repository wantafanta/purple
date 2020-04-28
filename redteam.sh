#!/bin/bash

# check ubuntu
DISTRIBUTION=$(grep "^ID=" /etc/os-release | cut -d\= -f2)
if [ ! $DISTRIBUTION == "ubuntu" ]; then
  echo "Nope. Only tested on Ubuntu, sorry." 1>&2
  exit 1
fi
# check sudo
if [[ $EUID = 0 ]]; then
  echo "Nope. Please run without sudo." 1>&2
  exit 1
fi
# check ubuntu version
py2_support() {
  local version=$(lsb_release -rs)
  local py2=$(if [[ $version == "20.04" ]]; then echo "false"; else echo "true"; fi)
  echo $py2
}

if [[ $(py2_support) == "false" ]]; then
  echo "Ubuntu 20.04 no longer supports Python 2, so the below tools won't be installed. If you need them, run this script on Ubuntu 19.10 ( https://releases.ubuntu.com/19.10/ )." 1>&2
  echo -e "\n-- crEAP\n-- Don't Kill MY Cat (DKMC)\n-- Jackit\n-- LinkedInt\n-- natlas\n-- ODAT: Oracle Database Attacking Tool\n-- PRET\n-- rdpy\n-- Seth\n-- SimplyEmail\n-- Spoofcheck\n-- tplmap\n-- Windows Exploit Suggester\n-- zenmap\n"
  echo "Press Enter to continue."
  read -p "" </dev/tty
fi

sudo bash -c 'echo -e "#!/bin/bash\nif [[ \$EUID = 0 ]]; then\n  echo \"1\"\n  exit 1\nfi\necho \"0\"" > /usr/bin/checksudo'
sudo chmod +x /usr/bin/checksudo

clear && echo "-- Lets begin ..."

# static urls (that may need to be updated)
URL_MONO='https://dl.winehq.org/wine/wine-mono/5.0.0/wine-mono-5.0.0-x86.msi'
# mono: https://dl.winehq.org/wine/wine-mono/
URL_OPENCL='http://registrationcenter-download.intel.com/akdlm/irc_nas/vcp/15532/l_opencl_p_18.1.0.015.tgz'
# opencl: https://software.intel.com/en-us/articles/opencl-runtime-release-notes/
URL_NESSUS='https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/10852/download?i_agree_to_tenable_license_agreement=true'
# nesus: https://www.tenable.com/downloads/nessus - Nessus-8.10.0-ubuntu1110_amd64.deb

# function to scrape latest release from github api
url_latest() {
  local json=$(curl -s $1)
  local url=$(echo "$json" | jq -r '.assets[].browser_download_url | select(contains("'$2'"))')
  echo $url
}

# get user ids
RUSER_UID=$(id -u ${USER}) # real user id

# no longer ask for password
echo "${USER} ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/dont-prompt-${USER}-for-password

# take owership of /opt/
sudo chown -R ${USER}:${USER} /opt/

# prepare os
clear && echo "-- Installing Ubuntu OS updates"
sudo apt-get -qq update && sudo apt-get -qq upgrade

clear && echo "-- Installing apt packages"
sudo apt-get -qq install open-vm-tools open-vm-tools-desktop net-tools git tmux whois ipcalc mlocate curl rename python3-pip libcanberra-gtk-module libgconf-2-4 jq gnome-tweak-tool wireguard
if [[ $(py2_support) == "false" ]]; then
  sudo apt-get -qq install python-is-python3
else
  sudo apt-get -qq install python-pip python-qt4
fi
sudo apt-get -qq install ruby-dev ruby-bundler #ruby for beef & wpscan
sudo apt-get -qq install chrome-gnome-shell #firefox gnome extensions pre-reqs

clear && echo "-- Installing pip modules"
if [[ $(py2_support) == "true" ]]; then
  sudo -H pip install -U pipenv
  sudo -H pip install service_identity rdpy
fi
sudo -H pip3 install -U pipenv
sudo -H pip3 install pypykatz shodan droopescan

clear && echo "Configuring TMUX"
echo 'set -g default-terminal "screen-256color"' > ~/.tmux.conf
sudo chown -R ${USER}:${USER} ~/.tmux.conf

clear && echo "-- Installing asciinema (terminal session recorder)" # https://github.com/asciinema/asciinema/
sudo -H pip3 install -U asciinema

clear && echo "-- Installing Firewall"
sudo apt-get -qq install gufw
sudo ufw disable

clear && echo "-- Installing FileZilla"
sudo apt-get -qq install filezilla

clear && echo "-- Installing FreeRDP"
sudo apt-get -qq install freerdp2-x11

clear && echo "-- Installing Kazam Screencaster"
sudo apt-get -qq install kazam

clear && echo "-- Installing nmap"
sudo apt-get -qq install nmap
if [[ $(py2_support) == "true" ]]; then # not in 20.04 repo
  clear && echo "-- Installing zenmap"
  sudo apt-get -qq install zenmap
fi
sudo wget -q 'https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse' -O '/usr/share/nmap/scripts/vulners.nse'
sudo git clone -q --depth 1 'https://github.com/scipag/vulscan' /usr/share/nmap/scripts/vulscan
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/cve.csv' -O '/usr/share/nmap/scripts/vulscan/cve.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/exploitdb.csv' -O '/usr/share/nmap/scripts/vulscan/exploitdb.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/openvas.csv' -O '/usr/share/nmap/scripts/vulscan/openvas.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/osvdb.csv' -O '/usr/share/nmap/scripts/vulscan/osvdb.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/scipvuldb.csv' -O '/usr/share/nmap/scripts/vulscan/scipvuldb.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/securityfocus.csv' -O '/usr/share/nmap/scripts/vulscan/securityfocus.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/securitytracker.csv' -O '/usr/share/nmap/scripts/vulscan/securitytracker.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/xforce.csv' -O '/usr/share/nmap/scripts/vulscan/xforce.csv'
sudo nmap --script-updatedb

clear && echo "-- Installing snaps"
sudo snap install powershell --classic
sudo snap install code --classic
sudo snap install docker
sudo snap install remmina
sudo snap connect remmina:avahi-observe :avahi-observe
sudo snap connect remmina:cups-control :cups-control
sudo snap connect remmina:mount-observe :mount-observe
sudo snap connect remmina:password-manager-service :password-manager-service
sudo snap install john-the-ripper

clear && echo "-- Cloning repositories"
cd /opt/

git clone -q --depth 1 'https://github.com/aanarchyy/bully'
git clone -q --depth 1 'https://github.com/actuated/msf-exploit-loop'
git clone -q --depth 1 'https://github.com/almandin/fuxploider'
git clone -q --depth 1 'https://github.com/BC-SECURITY/empire'
git clone -q --depth 1 'https://github.com/beefproject/beef'
git clone -q --depth 1 'https://github.com/bitsadmin/wesng'
git clone -q --depth 1 'https://github.com/BloodHoundAD/bloodhound'
#git clone -q --depth 1 --recursive 'https://github.com/byt3bl33d3r/crackmapexec'
git clone -q --depth 1 'https://github.com/byt3bl33d3r/silenttrinity'
git clone -q --depth 1 'https://github.com/byt3bl33d3r/sprayingtoolkit'
git clone -q --depth 1 --recurse-submodules 'https://github.com/cobbr/covenant'
git clone -q --depth 1 'https://github.com/commonexploits/vlan-hopping'
git clone -q --depth 1 'https://github.com/cve-search/cve-search'
git clone -q --depth 1 'https://github.com/D4Vinci/cr3dov3r'
git clone -q --depth 1 'https://github.com/daddycocoaman/beacongraph'
git clone -q --depth 1 'https://github.com/dafthack/mailsniper'
git clone -q --depth 1 'https://github.com/danielmiessler/seclists'
git clone -q --depth 1 'https://github.com/davidtavarez/pwndb'
git clone -q --depth 1 'https://github.com/denisidoro/navi'
git clone -q --depth 1 'https://github.com/dirkjanm/privexchange' #httpattack.py must be configured
git clone -q --depth 1 'https://github.com/drwetter/testssl.sh.git'
git clone -q --depth 1 'https://github.com/Ekultek/whatwaf'
git clone -q --depth 1 'https://github.com/evilmog/ntlmv1-multi'
git clone -q --depth 1 'https://github.com/FluxionNetwork/fluxion'
git clone -q --depth 1 'https://github.com/fox-it/bloodhound.py'
git clone -q --depth 1 'https://github.com/fox-it/mitm6'
git clone -q --depth 1 'https://github.com/Hackndo/lsassy'
git clone -q --depth 1 'https://gitlab.com/initstring/evil-ssdp'
git clone -q --depth 1 'https://github.com/jseidl/usernamer'
git clone -q --depth 1 'https://github.com/lanjelot/patator'
git clone -q --depth 1 'https://github.com/lanmaster53/recon-ng'
git clone -q --depth 1 'https://github.com/laramies/theharvester'
git clone -q --depth 1 'https://github.com/lgandx/responder'
git clone -q --depth 1 'https://github.com/lightos/credmap'
git clone -q --depth 1 --recursive 'https://github.com/m8r0wn/activereign'
git clone -q --depth 1 'https://github.com/m8r0wn/enumdb'
git clone -q --depth 1 'https://github.com/m8r0wn/nullinux'
git clone -q --depth 1 'https://github.com/m8r0wn/pymeta'
git clone -q --depth 1 --recursive 'https://github.com/mdsecresearch/lyncsniper'
git clone -q --depth 1 'https://github.com/mIcHyAmRaNe/okadminfinder3'
git clone -q --depth 1 'https://github.com/offensive-security/exploitdb'
git clone -q --depth 1 'https://github.com/Pepelux/sippts'
git clone -q --depth 1 'https://github.com/Proxmark/proxmark3'
git clone -q --depth 1 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries' ghostpack #https://github.com/GhostPack
git clone -q --depth 1 'https://github.com/rezasp/joomscan'
git clone -q --depth 1 'https://github.com/rbsec/dnscan'
git clone -q --depth 1 'https://github.com/s0lst1c3/eaphammer'
git clone -q --depth 1 'https://github.com/s0md3v/hash-buster'
git clone -q --depth 1 'https://github.com/s0md3v/photon'
git clone -q --depth 1 'https://github.com/s0md3v/xsstrike'
git clone -q --depth 1 'https://github.com/sachinkamath/ntlmrecon'
git clone -q --depth 1 --recursive 'https://github.com/Screetsec/sudomy'
git clone -q --depth 1 'https://github.com/sqlmapproject/sqlmap'
git clone -q --depth 1 'https://github.com/threat9/routersploit'
git clone -q --depth 1 'https://github.com/trustedsec/unicorn'
git clone -q --depth 1 'https://github.com/ustayready/fireprox'
git clone -q --depth 1 'https://github.com/wantafanta/nmapautomator'
git clone -q --depth 1 'https://github.com/ZerBea/hcxtools'
git clone -q --depth 1 'https://github.com/ZerBea/hcxdumptool'

#-- PRIVILEGE ESCALATION
git clone -q --depth 1 'https://github.com/PowerShellMafia/powersploit'
git clone -q --depth 1 'https://github.com/mzet-/linux-exploit-suggester'
git clone -q --depth 1 'https://github.com/diego-treitos/linux-smart-enumeration'

#-- SYSTEM AUDIT
git clone -q --depth 1 'https://github.com/CISOfy/lynis'

#-- /OPT/ SCRIPTS
bash -c 'echo -e "#!/bin/bash\nls | xargs -I{} git -C {} pull" > update.sh'
bash -c 'echo -e "#!/bin/bash\nsudo /usr/bin/vmhgfs-fuse .host:/ /mnt/hgfs/ -o subtype=vmhgfs-fuse,allow_other\nln -sf /mnt/hgfs/*/ ~/Desktop/" > map-shares.sh'
sudo chmod +x *.sh

#-- DESKTOP
gsettings set org.gnome.shell.extensions.desktop-icons show-home false
gsettings set org.gnome.shell.extensions.desktop-icons show-trash false
bash -c "echo -e '[Desktop Entry]\nName=Link to LOLBAS\nType=Application\nExec=firefox https://lolbas-project.github.io/\nIcon=firefox\nTerminal=false' > /home/${USER}/Desktop/LOLBAS.desktop"
bash -c "echo -e '[Desktop Entry]\nName=Link to GTFOBins\nType=Application\nExec=firefox https://gtfobins.github.io/\nIcon=firefox\nTerminal=false' > /home/${USER}/Desktop/GTFOBins.desktop"
sudo chown -R ${USER}:${USER} /home/${USER}/Desktop/*.desktop

#-- BASH ALIASES
bash -c "echo -e 'alias aquatone=\"/opt/aquatone/aquatone\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias cameradar=\"sudo docker run -t ullaakut/cameradar\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias creap=\"sudo /opt/creap/crEAP.py\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias dirble=\"/opt/dirble/dirble\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias enumdb=\"/opt/enumdb/enumdb.py\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias evil-ssdp=\"/opt/evil-ssdp/evil_ssdp.py\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias evilginx=\"sudo evilginx\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias frogger=\"sudo /opt/vlan-hopping/frogger2.sh\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias gowitness=\"/opt/gowitness/gowitness-linux-amd64\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias kerbrute=\"/opt/kerbrute/kerbrute_linux_amd64\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias nmapautomator=\"sudo /opt/nmapautomator/nmapAutomator.sh\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias nse=\"ls /usr/share/nmap/scripts/ | grep \"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias recursebuster=\"/opt/recursebuster/recursebuster_elf\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias responder=\"sudo /opt/responder/Responder.py\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias ruler=\"/opt/ruler/ruler-linux64\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias termshark=\"/opt/termshark/termshark\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias unicorn=\"/opt/unicorn/unicorn.py\"' >> /home/${USER}/.bash_aliases"
bash -c "echo -e 'alias usernamer=\"/opt/usernamer/usernamer.py\"' >> /home/${USER}/.bash_aliases"
#. ~/.bashrc

clear && echo "-- Installing Metasploit"
sudo apt-get -qq install postgresql
cd /opt/
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && sudo chmod 755 msfinstall && sudo ./msfinstall
sudo rm msfinstall
sudo wget -q 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/lib/msf/core/web_services/public/favicon.ico' -O '/opt/metasploit-framework/logo.ico'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Metasploit Framework\nExec=gnome-terminal --window -- sudo msfconsole\nIcon=/opt/metasploit-framework/logo.ico\nCategories=Application;" > /usr/share/applications/metasploit-framework.desktop'
sudo cp /opt/metasploit-framework/embedded/framework/config/database.yml.example /opt/metasploit-framework/embedded/framework/config/database.yml
sudo sed -i 's/^  password:.*/  password: msf/g' /opt/metasploit-framework/embedded/framework/config/database.yml
sudo -u postgres bash -c "psql -c \"CREATE USER metasploit_framework_development WITH PASSWORD 'msf';\""
sudo -u postgres bash -c "psql -c \"CREATE DATABASE metasploit_framework_development;\""
sudo -u postgres bash -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE metasploit_framework_development TO metasploit_framework_development;\""

clear && echo "-- Installing searchsploit"
sed 's|path_array+=(.*)|path_array+=("/opt/exploitdb")|g' /opt/exploitdb/.searchsploit_rc > ~/.searchsploit_rc
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

clear && echo "-- Installing routersploit"
cd /opt/routersploit/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/routersploit && if [ \$(checksudo) = 0 ]; then (pipenv run python3 rsf.py \"\$@\");fi)" > /usr/bin/rsf'
sudo chmod +x /usr/bin/rsf
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/routersploit && if [ \$(checksudo) = 0 ]; then (pipenv run python3 rsf.py \"\$@\");fi)" > /usr/bin/routersploit'
sudo chmod +x /usr/bin/routersploit

clear && echo "-- Installing MongoDB (cve-search Database)"
sudo apt-get -qq install mongodb

clear && echo "-- Installing Shellter (Community Edition)"
URL_SHELLTER='https://www.shellterproject.com/Downloads/Shellter/Latest/shellter.zip'
URL_SHELLTER_README='https://www.shellterproject.com/Downloads/Shellter/Readme.txt'
cd /opt/
wget -q -U firefox $URL_SHELLTER
unzip shellter.zip
sudo rm shellter.zip
cd /opt/shellter/
wget -q -U firefox $URL_SHELLTER_README
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/shellter && wine shellter.exe \"\$@\")" > /usr/bin/shellter'
sudo chmod +x /usr/bin/shellter

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing Don't Kill My Cat (DKMC)"
  git clone -q --depth 1 'https://github.com/Mr-Un1k0d3r/dkmc' /opt/dkmc
  cd /opt/dkmc/
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/dkmc/ && python dkmc.py \"\$@\")" > /usr/bin/dkmc'
  sudo chmod +x /usr/bin/dkmc
fi

clear && echo "-- Installing mimikatz"
URL_MIMIKATZ=$(url_latest 'https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest' 'mimikatz_trunk.zip')
mkdir /opt/mimikatz
wget -q $URL_MIMIKATZ -O '/opt/mimikatz/mimikatz.zip'
cd /opt/mimikatz/
unzip mimikatz.zip
sudo rm mimikatz.zip
#doesn't work in wine
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/mimikatz/x64/ && wine mimikatz.exe \"\$@\")" > /usr/bin/mimikatz'
#sudo chmod +x /usr/bin/mimikatz

clear && echo "-- Installing NtdsAudit"
URL_NTDSAUDIT=$(url_latest 'https://api.github.com/repos/Dionach/NtdsAudit/releases/latest' 'NtdsAudit.exe')
mkdir /opt/ntdsaudit
wget -q $URL_NTDSAUDIT -O '/opt/ntdsaudit/NtdsAudit.exe'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/ntdsaudit && wine NtdsAudit.exe \"\$@\")" > /usr/bin/ntdsaudit'
sudo chmod +x /usr/bin/ntdsaudit

clear && echo "-- Installing NTDSDumpEx"
URL_NTDSDUMPEX=$(url_latest 'https://api.github.com/repos/zcgonvh/NTDSDumpEx/releases/latest' 'NTDSDumpEx.zip')
cd /opt/
wget -q $URL_NTDSDUMPEX
unzip NTDSDumpEx.zip -d ntdsdumpex
sudo rm NTDSDumpEx.zip
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/ntdsdumpex && wine NTDSDumpEx.exe \"\$@\")" > /usr/bin/ntdsdumpex'
sudo chmod +x /usr/bin/ntdsdumpex
# on Domain Controller, run cmd as administrator
# ntdsutil "activate instance ntds" ifm "create full c:\x" quit quit

clear && echo "-- Installing Merlin"
URL_MERLIN=$(url_latest 'https://api.github.com/repos/Ne0nd0g/merlin/releases/latest' 'merlinServer-Linux-x64')
sudo apt-get -qq install p7zip-full
mkdir /opt/merlin
cd /opt/merlin/
wget -q $URL_MERLIN
7z x merlinServer*.7z -p'merlin'
sudo rm merlinServer-Linux-x64*.7z
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/merlin && sudo ./merlinServer-Linux-x64 \"\$@\")" > /usr/bin/merlin'
sudo chmod +x /usr/bin/merlin
sudo bash -c 'echo -e "#!/bin/bash\n(openssl req -x509 -newkey rsa:2048 -keyout /opt/merlin/data/x509/server.enc.key -out /opt/merlin/data/x509/server.crt -passout pass:merlin && openssl rsa -in /opt/merlin/data/x509/server.enc.key -out /opt/merlin/data/x509/server.key -passin pass:merlin \"\$@\")" > /usr/bin/merlin-cert'
sudo chmod +x /usr/bin/merlin-cert
wget -q 'https://camo.githubusercontent.com/c39b27165e5a911744220274b00b1bfcb2742408/68747470733a2f2f692e696d6775722e636f6d2f34694b7576756a2e6a7067' -O '/opt/merlin/logo.jpeg'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Merlin\nExec=gnome-terminal --window -- merlin\nIcon=/opt/merlin/logo.jpeg\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Generate Certificate\nExec=gnome-terminal --window -- merlin-cert" > /usr/share/applications/merlin.desktop'

if [[ $(py2_support) == "true" ]]; then
  clear && echo "Installing Windows Exploit Suggester"
  git clone -q --depth 1 'https://github.com/GDSSecurity/windows-exploit-suggester' /opt/windows-exploit-suggester
  sudo bash -c 'echo -e "#!/bin/bash\n(python2 /opt/windows-exploit-suggester/windows-exploit-suggester.py \"\$@\")" > /usr/bin/windows-exploit-suggester'
  sudo chmod +x /usr/bin/windows-exploit-suggester
fi

clear && echo "Installing Windows Exploit Suggester - Next Generation (wesng)"
cd /opt/wesng
sudo python3 setup.py install
#pipenv --bare --three run python3 setup.py install --record files.txt
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/wesng/ && if [ \$(checksudo) = 0 ]; then (pipenv run python3 wes.py \"\$@\");fi)" > /usr/bin/wesng'
#sudo chmod +x /usr/bin/wesng

clear && echo "-- Installing DNScan"
cd /opt/dnscan/
pipenv --bare --three install
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/dnscan/ && if [ \$(checksudo) = 0 ]; then (pipenv run python3 dnscan.py \"\$@\");fi)" > /usr/bin/dnscan'
sudo chmod +x /usr/bin/dnscan

#clear && echo "-- Installing DeathStar"
#cd /opt/deathstar/
#pipenv --bare --three install
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/deathstar/ && if [ \$(checksudo) = 0 ]; then (pipenv run python3 DeathStar.py \"\$@\");fi)" > /usr/bin/deathstar'
#sudo chmod +x /usr/bin/deathstar

clear && clear && echo "-- Installing Empire"
#echo
#echo "Empire PowerShell modules will require preobfuscation. When prompted, enter \`y\` twice."
#echo
#echo "Press Enter to continue."
#read -p "" </dev/tty
cd /opt/empire/
sudo apt-get -qq install python3-m2crypto
sudo ./setup/install.sh
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/empire && sudo ./empire \"\$@\")" > /usr/bin/empire'
sudo chmod +x /usr/bin/empire
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Empire\nExec=gnome-terminal --window -- empire\nIcon=/opt/empire/data/misc/apptemplateResources/icon/stormtrooper.icns\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Web UI\nExec=starkiller" > /usr/share/applications/empire.desktop'
bash -c 'echo -e "preobfuscate\nexit" > /opt/empire/obf.rc'
empire -r /opt/empire/obf.rc
sudo rm /opt/empire/obf.rc

clear && echo "-- Installing Starkiller (Empire GUI)"
cd /opt/
URL_STARKILLER=$(url_latest 'https://api.github.com/repos/BC-SECURITY/Starkiller/releases/latest' '.AppImage')
mkdir /opt/starkiller
wget -q $URL_STARKILLER -O '/opt/starkiller/starkiller.AppImage'
sudo chmod +x /opt/starkiller/starkiller.AppImage
sudo ln -sf /opt/starkiller/starkiller.AppImage /usr/local/bin/starkiller
wget -q 'https://raw.githubusercontent.com/BC-SECURITY/Starkiller/master/src/assets/icon.png' -O '/opt/starkiller/icon.png'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Starkiller\nExec=starkiller\nIcon=/opt/starkiller/icon.png\nCategories=Application;" > /usr/share/applications/starkiller.desktop'

clear && echo "-- Installing Dotnet Core 2.2 (Covenant)"
cd /opt/
wget -q 'https://download.visualstudio.microsoft.com/download/pr/022d9abf-35f0-4fd5-8d1c-86056df76e89/477f1ebb70f314054129a9f51e9ec8ec/dotnet-sdk-2.2.207-linux-x64.tar.gz'
mkdir -p /opt/dotnet && tar zxf dotnet-sdk-*.tar.gz -C /opt/dotnet
sudo ln -sf /opt/dotnet/dotnet /usr/bin/dotnet
export DOTNET_ROOT=/opt/dotnet
export PATH=$PATH:/opt/dotnet
sudo rm -r dotnet-sdk-*.tar.gz

clear && echo "-- Installing Covenant"
cd /opt/covenant/Covenant/
sudo dotnet build
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/covenant/Covenant/ && sudo dotnet run \"\$@\")" > /usr/bin/covenant'
sudo chmod +x /usr/bin/covenant
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Covenant\nExec=gnome-terminal --window -- covenant\nIcon=/opt/covenant/Covenant/wwwroot/images/favicon.svg\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Web UI\nExec=firefox https://localhost:7443" > /usr/share/applications/covenant.desktop'

clear && echo "-- Installing mitm6"
cd /opt/mitm6/
pipenv --bare --three run sudo pip3 install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/mitm6/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo mitm6 \"\$@\");fi)" > /usr/bin/mitm6'
sudo chmod +x /usr/bin/mitm6

clear && echo "-- Installing Impacket"
URL_IMPACKET=$(url_latest 'https://api.github.com/repos/SecureAuthCorp/impacket/releases/latest' 'impacket')
cd /opt/
wget -q $URL_IMPACKET
tar xvf impacket*.tar.gz
sudo rm impacket-*.tar.gz
mv impacket-*/ impacket/
cd /opt/impacket/
sudo -H pip3 install -r requirements.txt
sudo -H pip3 install .

clear && echo "-- Installing lsassy"
cd /opt/lsassy/
pipenv --bare --three install lsassy
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/lsassy/ && if [ \$(checksudo) = 0 ]; then (pipenv run lsassy \"\$@\");fi)" > /usr/bin/lsassy'
sudo chmod +x /usr/bin/lsassy

clear && echo "-- Installing CrackMapExec"
URL_CME=$(url_latest 'https://api.github.com/repos/byt3bl33d3r/CrackMapExec/releases/latest' 'cme-ubuntu')
URL_CMEDB=$(url_latest 'https://api.github.com/repos/byt3bl33d3r/CrackMapExec/releases/latest' 'cmedb-ubuntu')
mkdir /opt/crackmapexec/
cd /opt/crackmapexec/
wget -q $URL_CME
wget -q $URL_CMEDB
unzip cme-ubuntu-latest.zip
unzip cmedb-ubuntu-latest.zip
sudo rm cme*.zip
sudo chmod +x cme*
sudo ln -sf /opt/crackmapexec/cme /usr/local/bin/cme
sudo ln -sf /opt/crackmapexec/cmedb /usr/local/bin/cmedb

clear && echo "-- Installing ActiveReign"
cd /opt/activereign/
pipenv --bare --three run python3 setup.py install --record files.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/activereign/ && if [ \$(checksudo) = 0 ]; then (pipenv run activereign \"\$@\");fi)" > /usr/bin/activereign'
sudo chmod +x /usr/bin/activereign
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/activereign/ && if [ \$(checksudo) = 0 ]; then (pipenv run activereign \"\$@\");fi)" > /usr/bin/ar3'
sudo chmod +x /usr/bin/ar3

clear && echo "-- Installing BloodHound"
URL_BLOODHOUND=$(url_latest 'https://api.github.com/repos/BloodHoundAD/BloodHound/releases/latest' 'linux-x64')
cd /opt/
wget -q $URL_BLOODHOUND
unzip BloodHound-linux-x64.zip
sudo rm BloodHound*.zip
mv BloodHound-linux-x64/ bloodhound-bin/
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=BloodHound\nExec=\"/opt/bloodhound-bin/BloodHound\"\nIcon=/opt/bloodhound/src/img/icon.ico\nCategories=Application;" > /usr/share/applications/bloodhound.desktop'

clear && echo "-- Installing Neo4j (BloodHound Database)"
cd /opt/
sudo apt-get remove -y java-common
sudo apt-get -qq install openjdk-8-jre-headless
wget -q --no-check-certificate -O - 'https://debian.neo4j.org/neotechnology.gpg.key' | sudo apt-key add -
echo 'deb http://debian.neo4j.org/repo stable/' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
sudo apt-get -qq update
sudo apt-get -qq install neo4j
sudo systemctl enable neo4j.service

clear && echo "-- Installing BloodHound Custom Queries"
mkdir ~/.config/bloodhound
curl 'https://raw.githubusercontent.com/hausec/Bloodhound-Custom-Queries/master/customqueries.json' > ~/.config/bloodhound/customqueries.json

clear && echo "-- Installing bloodhound.py"
cd /opt/bloodhound.py/
pipenv --bare --three run python3 setup.py install --record files.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/bloodhound.py/ && if [ \$(checksudo) = 0 ]; then (pipenv run python3 bloodhound.py \"\$@\");fi)" > /usr/bin/bloodhound.py'
sudo chmod +x /usr/bin/bloodhound.py

clear && echo "-- Installing Aclpwn" #Active Directory ACL exploitation with BloodHound
#https://github.com/fox-it/aclpwn.py
sudo -H pip3 install aclpwn

clear && echo "-- Installing Torghost"
cd /opt/
sudo apt-get -qq install tor
sudo systemctl disable tor.service
URL_TORGHOST=$(url_latest 'https://api.github.com/repos/SusmithKrishnan/torghost/releases/latest' 'amd64.deb')
wget -q $URL_TORGHOST
sudo dpkg -i torghost-*-amd64.deb
sudo rm torghost-*-amd64.deb
#firefox http://about:config
#set network.dns.blockDotOnion;false

clear && echo "-- Installing onionshare"
sudo add-apt-repository -y ppa:micahflee/ppa
sudo apt-get update
sudo apt-get -qq install onionshare

clear && echo "-- Installing fireprox"
cd /opt/fireprox/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/fireprox && if [ \$(checksudo) = 0 ]; then (pipenv run python3 fire.py \"\$@\");fi)" > /usr/bin/fireprox'
sudo chmod +x /usr/bin/fireprox

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing SimplyEmail"
  git clone -q --depth 1 'https://github.com/SimplySecurity/simplyemail' /opt/simplyemail
  sudo apt-get -qq install python-lxml grep antiword odt2txt python-dev libxml2-dev libxslt1-dev
  cd /opt/simplyemail/
  pipenv --bare --two install -r setup/req*.txt
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/simplyemail && if [ \$(checksudo) = 0 ]; then (pipenv run python2.7 SimplyEmail.py \"\$@\");fi)" > /usr/bin/simplyemail'
  sudo chmod +x /usr/bin/simplyemail

  clear && echo "-- Installing JackIt"
  git clone -q --depth 1 'https://github.com/insecurityofthings/jackit' /opt/jackit
  cd /opt/jackit/
  pipenv --bare --two run sudo python2 setup.py install --record files.txt
  sudo rm /usr/local/bin/jackit
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/jackit/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo bin/jackit \"\$@\");fi)" > /usr/bin/jackit'
  sudo chmod +x /usr/bin/jackit

  clear && echo "-- Installing spoofcheck"
  git clone -q --depth 1 'https://github.com/BishopFox/spoofcheck' /opt/spoofcheck
  cd /opt/spoofcheck/
  pipenv --bare --two run sudo pip2 install -r requirements.txt
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/spoofcheck/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python2 spoofcheck.py \"\$@\");fi)" > /usr/bin/spoofcheck'
  sudo chmod +x /usr/bin/spoofcheck
fi

clear && echo "-- Installing Camradar (docker)"
sudo docker pull ullaakut/cameradar
#sudo docker run -t ullaakut/cameradar -h

clear && echo "-- Installing credmap"
cd /opt/credmap/
sudo chmod +x credmap.py
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/credmap/ && python credmap.py \"\$@\")" > /usr/bin/credmap'
sudo chmod +x /usr/bin/credmap

clear && echo "-- Installing Google Chrome (Stable)" #for gowitness
wget -q -O - 'https://dl-ssl.google.com/linux/linux_signing_key.pub' | sudo apt-key add -
echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt-get -qq update
sudo apt-get -qq install google-chrome-stable

clear && echo "-- Installing gowitness"
URL_GOWITNESS=$(url_latest 'https://api.github.com/repos/sensepost/gowitness/releases/latest' 'linux-amd64')
mkdir /opt/gowitness
cd /opt/gowitness
wget -q $URL_GOWITNESS
sudo chmod +x gowitness-linux-amd64

clear && echo "-- Installing Chromium Browser" #for aquatone
sudo apt-get -qq install chromium-browser

clear && echo "-- Installing aquatone"
URL_AQUATONE=$(url_latest 'https://api.github.com/repos/michenriksen/aquatone/releases/latest' 'linux_amd64')
mkdir /opt/aquatone
cd /opt/aquatone
wget -q $URL_AQUATONE
unzip aquatone*.zip
sudo rm aquatone*.zip
sudo chmod +x aquatone

clear && echo "-- Installing ruler"
URL_RULER=$(url_latest 'https://api.github.com/repos/sensepost/ruler/releases/latest' 'linux64')
mkdir /opt/ruler
cd /opt/ruler/
wget -q $URL_RULER
sudo chmod +x ruler-linux64

clear && echo "-- Installing SilentTrinity"
cd /opt/silenttrinity/
wget -q 'https://user-images.githubusercontent.com/5151193/45964397-e462e280-bfe2-11e8-88a7-69212e0f0355.png' -O '/opt/silenttrinity/logo.png'
pipenv --bare --three run sudo pip3 install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/silenttrinity/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 st.py \"\$@\");fi)" > /usr/bin/silenttrinity'
sudo chmod +x /usr/bin/silenttrinity
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=SilentTrinity\nExec=gnome-terminal --window -- silenttrinity client\nIcon=/opt/silenttrinity/logo.png\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Start Teamserver\nExec=gnome-terminal --window -- bash -c '\''printf \"\\\n\\\n\" && nmcli d show | grep .ADDRESS && printf \"\\\n\\\n\" && read -p \"Enter the IP address to use: \" ip &&  read -p \"Enter the password to use: \" pass && clear && silenttrinity teamserver \$ip \$pass'\''\n" > /usr/share/applications/silenttrinity.desktop'

if [[ $(py2_support) == "true" ]]; then # pip requirements compile errors
  clear && echo "-- Installing SprayingToolkit"
  cd /opt/sprayingtoolkit/
  pipenv --bare --three run sudo pip3 install -r requirements.txt
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sprayingtoolkit/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 aerosol.py \"\$@\");fi)" > /usr/bin/aerosol'
  sudo chmod +x /usr/bin/aerosol
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sprayingtoolkit/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 atomizer.py \"\$@\");fi)" > /usr/bin/atomizer'
  sudo chmod +x /usr/bin/atomizer
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sprayingtoolkit/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 spindrift.py \"\$@\");fi)" > /usr/bin/spindrift'
  sudo chmod +x /usr/bin/spindrift
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sprayingtoolkit/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 vaporizer.py \"\$@\");fi)" > /usr/bin/vaporizer'
  sudo chmod +x /usr/bin/vaporizer
fi

########## ---------- ##########
# Generic
########## ---------- ##########

clear && echo "-- Installing DBeaver"
URL_DBEAVER='https://dbeaver.io/files/dbeaver-ce_latest_amd64.deb'
cd /opt/
wget -q $URL_DBEAVER
sudo apt-get -qq install ./dbeaver*.deb
sudo rm dbeaver*.deb

clear && echo "-- Installing Sqlectron"
URL_SQLECTRON=$(url_latest 'https://api.github.com/repos/sqlectron/sqlectron-gui/releases/latest' 'amd64')
cd /opt/
wget -q $URL_SQLECTRON
sudo apt-get -qq install ./Sqlectron*.deb
sudo rm Sqlectron*.deb

clear && echo "-- Installing nullinux"
cd /opt/nullinux/
sudo apt-get -qq install smbclient
sudo bash setup.sh

clear && echo "-- Installing enumdb"
cd /opt/enumdb/
sudo chmod +x setup.sh
sudo ./setup.sh

clear && echo "-- Installing File Cracks"
sudo apt-get -qq install fcrackzip

clear && echo "-- Installing NFS Utils"
sudo apt-get -qq install nfs-common

clear && echo "-- Installing GPS Utils"
sudo apt-get -qq install gpsd gpsd-clients

clear && echo "-- Installing navi" # will be good to use with some pentest .cheat files
sudo apt-get -qq install fzf
cd /opt/navi/
sudo make install

########## ---------- ##########
# Brute-force
########## ---------- ##########

clear && echo "-- Installing patator"
cd /opt/patator/
sudo apt-get -qq install libcurl4-openssl-dev python3-dev libssl-dev # pycurl
sudo apt-get -qq install ldap-utils # ldapsearch
sudo apt-get -qq install libmysqlclient-dev # mysqlclient-python
sudo apt-get -qq install ike-scan unzip default-jdk
sudo apt-get -qq install libsqlite3-dev libsqlcipher-dev # pysqlcipher
pipenv --bare --three run sudo python setup.py install --record files.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/patator/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo patator.py \"\$@\");fi)" > /usr/bin/patator'
sudo chmod +x /usr/bin/patator

clear && echo "-- Installing kerbrute"
URL_KERBRUTE=$(url_latest 'https://api.github.com/repos/ropnop/kerbrute/releases/latest' 'linux_amd64')
mkdir /opt/kerbrute
cd /opt/kerbrute/
wget -q $URL_KERBRUTE
sudo chmod +x kerbrute_linux_amd64

########## ---------- ##########
# VoIP
########## ---------- ##########

clear && echo "-- Installing sippts"
sudo cpan -i IO:Socket:Timeout NetAddr:IP String:HexConvert Net:Pcap Net::Address::IP::Local DBI DBD::SQLite
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipscan.pl \"\$@\")" > /usr/bin/sipscan'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipexten.pl \"\$@\")" > /usr/bin/sipexten'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipcrack.pl \"\$@\")" > /usr/bin/sipcrack'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipinvite.pl \"\$@\")" > /usr/bin/sipinvite'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipsniff.pl \"\$@\")" > /usr/bin/sipsniff'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipspy.pl \"\$@\")" > /usr/bin/sipspy'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipdigestleak.pl \"\$@\")" > /usr/bin/sipdigestleak'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipreport.pl \"\$@\")" > /usr/bin/sipreport'
sudo chmod +x /usr/bin/sip*

########## ---------- ##########
# Wireless
########## ---------- ##########

clear && echo "-- Installing aircrack and mdk3"
sudo apt-get -qq install aircrack-ng mdk3

clear && echo "Updating OUI Database"
sudo airodump-ng-oui-update

clear && echo "-- Installing coWPAtty"
URL_COWPATTY='http://www.willhackforsushi.com/code/cowpatty/4.6/cowpatty-4.6.tgz'
sudo apt-get -qq install libpcap-dev
cd /opt/
wget -q $URL_COWPATTY
tar xvzf cowpatty-*.tgz
sudo rm -r cowpatty-*.tgz
cd cowpatty*
sudo make && sudo make install
cd /opt/
sudo rm -r cowpatty-*

clear && echo "-- Installing Fluxion"
sudo apt-get -qq install hostapd lighttpd macchanger mdk4 dsniff php-cgi xterm isc-dhcp-server
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/fluxion && ./fluxion.sh \"\$@\")" > /usr/bin/fluxion'
sudo chmod +x /usr/bin/fluxion
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Fluxion\nExec=gnome-terminal --window -- sudo fluxion\nIcon=/opt/fluxion/logos/logo.jpg\nCategories=Application;" > /usr/share/applications/fluxion.desktop'

#clear && echo "-- Installing BeaconGraph"
#cd /opt/beacongraph/
#pipenv --bare --three install -r requirements.txt
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/beacongraph/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 BeaconGraph.py \"\$@\");fi)" > /usr/bin/beacongraph'
#sudo chmod +x /usr/bin/beacongraph

########## ---------- ##########
# Password Cracking
########## ---------- ##########

clear && echo "-- Installing hashcat"
URL_HASHCAT=$(url_latest 'https://api.github.com/repos/hashcat/hashcat/releases/latest' 'hashcat')
cd /opt/
wget -q $URL_HASHCAT
7zr x hashcat-*.7z
sudo rm hashcat-*.7z
mv hashcat-*/ hashcat/
sudo ln -sf /opt/hashcat/hashcat64.bin /usr/local/bin/hashcat
# allows hashcat to work using cpu
# https://software.intel.com/en-us/articles/opencl-drivers#latest_CPU_runtime
cd /opt/
wget -q $URL_OPENCL
tar xvzf l_opencl_*.tgz
sudo rm -r l_opencl_*.tgz
cd l_opencl_*
sudo apt-get -qq install lsb-core
echo -e "ACCEPT_EULA=accept\nCONTINUE_WITH_OPTIONAL_ERROR=yes\nPSET_INSTALL_DIR=/opt/intel\nCONTINUE_WITH_INSTALLDIR_OVERWRITE=yes\nPSET_MODE=install\nINTEL_SW_IMPROVEMENT_PROGRAM_CONSENT=no\nCOMPONENTS=;intel-openclrt__x86_64;intel-openclrt-pset" > settings.cfg
sudo bash install.sh --silent settings.cfg
cd /opt/
sudo rm -r l_opencl_*

clear && echo "-- Installing hashcat-utils"
URL_HASHCAT_UTILS=$(url_latest 'https://api.github.com/repos/hashcat/hashcat-utils/releases/latest' 'hashcat-utils')
cd /opt/
wget -q $URL_HASHCAT_UTILS
7zr x hashcat-utils-*.7z
sudo rm hashcat-utils-*.7z
mv hashcat-utils-*/ hashcat-utils/

########## ---------- ##########
# Web
########## ---------- ##########

# burp suite community or pro
if [ ! -f ~/Downloads/burpsuite_pro_linux*.sh ] #burp professional installation script not found - ask if required
then
  clear
  echo "Burp Suite Professional installation script not found."
  echo -e "\nDownload \`burpsuite_pro_linux*.sh\` from: https://portswigger.net/users/youraccount"
  echo -e "\nSave this to ~/Downloads/burpsuite_pro_linux*.sh, otherwise the Community Edition will be installed."
  echo -e "\nPress Enter to continue (or skip)."
  read -p "" </dev/tty
  if [ ! -f ~/Downloads/burpsuite_pro_linux*.sh ] #burp professional not required, install burp community edition
  then
    clear && echo "-- Installing Burp Suite Community Edition"
    curl 'https://portswigger.net/burp/releases/download?product=community&type=linux' -o /opt/install.sh && sudo chmod +x /opt/install.sh
    sudo /opt/install.sh -dir /opt/burpsuitecommunity -overwrite -q
    sudo rm /opt/install.sh
    sudo mv /usr/share/applications/*BurpSuiteCommunity.desktop /usr/share/applications/BurpSuiteCommunity.desktop
    #sudo bash -c "echo -e 'StartupWMClass=com-install4j-runtime-launcher-UnixLauncher' >> '/usr/share/applications/BurpSuiteCommunity.desktop'"
  fi
fi
if [ -f ~/Downloads/burpsuite_pro_linux*.sh ] #burp professional installation script found, install burp professional
then
  clear && echo "-- Installing Burp Suite Professional Edition"
  sudo bash ~/Downloads/burpsuite_pro_linux*.sh -dir /opt/burpsuitepro -overwrite -q
  #sudo rm ~/Downloads/burpsuite_pro_linux*.sh
  sudo rename -d "s/(?:.*)BurpSuitePro.desktop/BurpSuitePro.desktop/" /usr/share/applications/*BurpSuitePro.desktop
  sudo bash -c "echo -e 'StartupWMClass=com-install4j-runtime-launcher-UnixLauncher' >> '/usr/share/applications/BurpSuitePro.desktop'"
fi
# download jython (burp extensions)
wget -q 'http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.0/jython-standalone-2.7.0.jar' -O "/home/${USER}/Documents/jython-standalone-2.7.0.jar"

clear && echo "-- Installing sqlmap"
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sqlmap/ && python3 sqlmap.py \"\$@\")" > /usr/bin/sqlmap'
sudo chmod +x /usr/bin/sqlmap

clear && echo "-- Installing jsql-injection"
URL_JSQL=$(url_latest 'https://api.github.com/repos/ron190/jsql-injection/releases/tags/v0.82' '.jar')
mkdir /opt/jsql-injection/
wget -q $URL_JSQL -O '/opt/jsql-injection/jsql-injection.jar'
wget -q 'https://raw.githubusercontent.com/ron190/jsql-injection/master/src/main/resources/swing/images/software/bug128.png' -O '/opt/jsql-injection/logo.png'
sudo bash -c 'echo -e "#!/bin/bash\n(java -jar /opt/jsql-injection/jsql-injection.jar \"\$@\")" > /usr/bin/jsql'
sudo chmod +x /usr/bin/jsql
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=jSQL Injection\nExec=gnome-terminal --window -- jsql\nIcon=/opt/jsql-injection/logo.png\nCategories=Application;" > /usr/share/applications/jsql.desktop'

clear && echo "-- Installing Whatwaf"
cd /opt/whatwaf/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/whatwaf && if [ \$(checksudo) = 0 ]; then (pipenv run python3 whatwaf.py \"\$@\");fi)" > /usr/bin/whatwaf'
sudo chmod +x /usr/bin/whatwaf

clear && echo "-- Installing nikto"
sudo apt-get -qq install nikto
nikto -update

clear && echo "-- Installing testssl.sh"
sudo bash -c 'echo -e "#!/bin/bash\n(/opt/testssl.sh/testssl.sh \"\$@\")" > /usr/bin/testssl.sh'
sudo chmod +x /usr/bin/testssl.sh

clear && echo "-- Installing Gobuster"
sudo apt-get -qq install gobuster
#dirbuster directory lists
URL_DIRBUSTER_LISTS='https://netix.dl.sourceforge.net/project/dirbuster/DirBuster%20Lists/Current/DirBuster-Lists.tar.bz2'
cd /opt/
wget -q $URL_DIRBUSTER_LISTS
tar xvf DirBuster-Lists.tar.bz2
mv DirBuster-Lists dirbuster-lists
sudo rm DirBuster-Lists.tar.bz2

clear && echo "-- Installing dirble"
URL_DIRBLE=$(url_latest 'https://api.github.com/repos/nccgroup/dirble/releases/latest' 'x86_64-linux')
cd /opt/
wget -q $URL_DIRBLE
unzip dirble*.zip
sudo rm dirble*.zip

clear && echo "-- Installing recursebuster"
URL_RECURSEBUSTER=$(url_latest 'https://api.github.com/repos/C-Sto/recursebuster/releases/latest' 'recursebuster_elf')
URL_RECURSEBUSTER_README='https://raw.githubusercontent.com/C-Sto/recursebuster/master/README.md'
mkdir /opt/recursebuster
cd /opt/recursebuster/
wget -q $URL_RECURSEBUSTER
wget -q $URL_RECURSEBUSTER_README
sudo chmod +x recursebuster_elf

clear && echo "-- Installing okadminfinder3"
cd /opt/okadminfinder3/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/okadminfinder3 && if [ \$(checksudo) = 0 ]; then (pipenv run python3 okadminfinder.py \"\$@\");fi)" > /usr/bin/okadminfinder3'
sudo chmod +x /usr/bin/okadminfinder3

clear && echo "-- Installing XSStrike"
cd /opt/xsstrike/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/xsstrike && if [ \$(checksudo) = 0 ]; then (pipenv run python3 xsstrike.py \"\$@\");fi)" > /usr/bin/xsstrike'
sudo chmod +x /usr/bin/xsstrike
URL_GECKODRIVER=$(url_latest 'https://api.github.com/repos/mozilla/geckodriver/releases/latest' 'linux64')
curl -s -L "$URL_GECKODRIVER" | tar -xz
sudo chmod +x geckodriver
sudo mv geckodriver '/usr/local/bin'

clear && echo "-- Installing WPScan"
sudo gem install wpscan
wpscan --update

clear && echo "-- Installing joomscan"
perl -i -pe 'y|\r||d' /opt/joomscan/joomscan.pl
sudo bash -c 'echo -e "#!/bin/bash\n(/opt/joomscan/joomscan.pl \"\$@\")" > /usr/bin/joomscan'
sudo chmod +x /usr/bin/joomscan

if [[ $(py2_support) == "true" ]]; then # requires python 3.6, 3.8 used in Ubuntu 20.04
  clear && echo "-- Installing ODAT: Oracle Database Attacking Tool"
  URL_ODAT=$(url_latest 'https://api.github.com/repos/quentinhardy/odat/releases/latest' 'x86_64')
  cd /opt/
  wget -q $URL_ODAT
  tar xvf odat*.tar.gz
  sudo rm odat*.tar.gz
  unzip odat*.zip
  sudo rm odat*.zip
  mv odat*/ odat/
  sudo ln -sf /opt/odat/odat* /usr/local/bin/odat
fi

clear && echo "-- Installing fuxploider"
cd /opt/fuxploider/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/fuxploider && if [ \$(checksudo) = 0 ]; then (pipenv run python3 fuxploider.py \"\$@\");fi)" > /usr/bin/fuxploider'
sudo chmod +x /usr/bin/fuxploider

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing tplmap"
  git clone -q --depth 1 'https://github.com/epinna/tplmap' /opt/tplmap
  cd /opt/tplmap/
  pipenv --bare --two install -r requirements.txt
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/tplmap && if [ \$(checksudo) = 0 ]; then (pipenv run python2 tplmap.py \"\$@\");fi)" > /usr/bin/tplmap'
  sudo chmod +x /usr/bin/tplmap
fi

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

clear && echo "-- Installing nmapAutomator"
cd /opt/nmapautomator/
sudo chmod +x nmapAutomator.sh
#sslscan, gobuster, nikto, joomscan, wpscan, droopescan, smbmap, smbclient, enum4linux, snmp-check, snmpwalk, dnsrecon, odat.py, 

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing Seth"
  git clone -q --depth 1 'https://github.com/SySS-Research/seth' /opt/seth
  cd /opt/seth/
  pipenv --bare --two install
  sudo apt-get -qq install dsniff
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/seth/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo ./seth.sh \"\$@\");fi)" > /usr/bin/seth'
  sudo chmod +x /usr/bin/seth
fi

clear && echo "-- Installing Wireshark"
sudo apt-get -qq install wireshark
sudo chmod +x /usr/bin/dumpcap
#to change user permission with gui: sudo dpkg-reconfigure wireshark-common
usermod -a -G wireshark ${USER}

clear && echo "-- Installing termshark"
sudo apt-get -qq install tshark
URL_TERMSHARK=$(url_latest 'https://api.github.com/repos/gcla/termshark/releases/latest' 'linux_x64')
cd /opt/
wget -q $URL_TERMSHARK
tar xvf termshark*.tar.gz
sudo rm termshark*.tar.gz
mv termshark_*/ termshark/

clear && echo "-- Installing bettercap"
URL_BETTERCAP=$(url_latest 'https://api.github.com/repos/bettercap/bettercap/releases/latest' 'bettercap_linux_amd64_')
sudo apt-get -qq install libnetfilter-queue-dev
mkdir /opt/bettercap
cd /opt/bettercap/
wget -q $URL_BETTERCAP
unzip -o bettercap_linux_amd64_*.zip
sudo rm bettercap*.zip
wget -q 'https://raw.githubusercontent.com/bettercap/media/master/logo.png' -O '/opt/bettercap/logo.png'
sudo ./bettercap -eval "caplets.update; ui.update; q"
sudo sed -i 's/^set api.rest.username.*/set api.rest.username admin/g' /usr/local/share/bettercap/caplets/http-ui.cap
sudo sed -i 's/^set api.rest.password.*/set api.rest.password bettercap/g' /usr/local/share/bettercap/caplets/http-ui.cap
sudo bash -c 'echo -e "#!/bin/bash\n(sudo /opt/bettercap/bettercap \"\$@\")" > /usr/bin/bettercap'
sudo chmod +x /usr/bin/bettercap
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=bettercap\nExec=gnome-terminal --window -- bash -c '\''printf \"\\\n\\\n\" && nmcli d && printf \"\\\n\\\n\" && read -p \"Enter the device name: \" int && clear && sudo /opt/bettercap/bettercap -iface \$int -caplet http-ui'\''\nIcon=/opt/bettercap/logo.png\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Web UI\nExec=firefox http://localhost:80" > /usr/share/applications/bettercap.desktop'

clear && echo "-- Installing BeEF"
sudo apt-get -qq install ruby ruby-dev
cd /opt/beef/
bundle config set without 'test development'
bundle install
sudo ./update-geoipdb
sudo sed -i 's/passwd: "beef"/passwd: "admin"/g' /opt/beef/config.yaml
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/beef && ./beef \"\$@\")" > /usr/bin/beef'
sudo chmod +x /usr/bin/beef
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=BeEF\nExec=gnome-terminal --window -- beef\nIcon=/opt/beef/extensions/admin_ui/media/images/beef.png\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Web UI\nExec=firefox http://localhost:3000/ui/panel" > /usr/share/applications/beef.desktop'

clear && echo "-- Installing wine"
sudo apt-get -qq install wine winbind winetricks xdotool
sudo dpkg --add-architecture i386 && sudo apt-get -qq update && sudo apt-get -qq install wine32
bash -c 'WINEARCH=win32 wine wineboot'

clear && echo "-- Installing FUZZBUNCH"
git clone -q --depth 1 'https://github.com/mdiazcl/fuzzbunch-debian' $HOME/.wine/drive_c/fuzzbunch-debian
bash -c "echo -e 'Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\\Environment]\n\"Path\"=\"c:\\\\\windows;c:\\\\\windows\\\\\system;C:\\\\\Python26;C:\\\\\\\fuzzbunch-debian\\\\\windows\\\\\\\fuzzbunch\"' > /home/${USER}/.wine/drive_c/system.reg"
bash -c "wine regedit.exe /s c:\\\system.reg"
bash -c "wine start /w c:\\\fuzzbunch-debian\\\installers\\\python-2.6.msi"
bash -c "wine start /w c:\\\fuzzbunch-debian\\\installers\\\pywin32-219.win32-py2.6.exe"
mkdir /opt/fuzzbunch
wget -q 'https://upload.wikimedia.org/wikipedia/commons/8/8d/Seal_of_the_U.S._National_Security_Agency.svg' -O '/opt/fuzzbunch/logo.svg'
sudo bash -c 'echo -e "#!/bin/bash\n(cd \$HOME/.wine/drive_c/fuzzbunch-debian/windows && wine cmd.exe /C python fb.py \"\$@\")" > /usr/bin/fuzzbunch'
sudo chmod +x /usr/bin/fuzzbunch
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=FUZZBUNCH\nExec=gnome-terminal --window -- fuzzbunch\nIcon=/opt/fuzzbunch/logo.svg\nCategories=Application;" > /usr/share/applications/fuzzbunch.desktop'

clear && echo "-- Installing EvilClippy"
URL_EVILCLIPPY=$(url_latest 'https://api.github.com/repos/outflanknl/EvilClippy/releases/latest' 'EvilClippy.exe')
URL_EVILCLIPPY_MCDF=$(url_latest 'https://api.github.com/repos/outflanknl/EvilClippy/releases/latest' 'OpenMcdf.dll')
URL_EVILCLIPPY_README='https://raw.githubusercontent.com/outflanknl/EvilClippy/master/README.md'
mkdir /opt/evilclippy
cd /opt/evilclippy/
wget -q $URL_EVILCLIPPY
wget -q $URL_EVILCLIPPY_MCDF
wget -q $URL_EVILCLIPPY_README
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/evilclippy/ && wine EvilClippy.exe \"\$@\")" > /usr/bin/evilclippy'
sudo chmod +x /usr/bin/evilclippy
sudo mkdir /usr/share/wine/mono
sudo wget -q $URL_MONO -O '/usr/share/wine/mono/wine-mono.msi'
bash -c "wine msiexec /i /usr/share/wine/mono/wine-mono.msi"

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing PRET"
  git clone -q --depth 1 'https://github.com/RUB-NDS/pret' /opt/pret
  cd /opt/pret/
  pipenv --bare --two install colorama pysnmp
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/pret/ && if [ \$(checksudo) = 0 ]; then (pipenv run python2 pret.py \"\$@\");fi)" > /usr/bin/pret'
  sudo chmod +x /usr/bin/pret
fi

clear && echo "-- Installing snmpwalk"
sudo apt-get -qq install snmp

clear && echo "-- Installing nbtscan"
sudo apt-get -qq install nbtscan

clear && echo "-- Installing NTLMRecon"
cd /opt/ntlmrecon/
pipenv --bare --three run python3 setup.py install --record files.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/ntlmrecon && if [ \$(checksudo) = 0 ]; then (pipenv run ntlmrecon \"\$@\");fi)" > /usr/bin/ntlmrecon'
sudo chmod +x /usr/bin/ntlmrecon

clear && echo "-- Installing Nessus"
cd /opt/
curl -O -J -L $URL_NESSUS
mv Nessus*.deb ~/Downloads/
while [ ! -f ~/Downloads/Nessus*.deb ] #nessus installation package not found - ask if required
do
  clear
  echo -e "Nessus installation package not found."
  echo -e "\nDownload \`Nessus-*-ubuntu*_amd64.deb\` from: https://www.tenable.com/downloads/nessus"
  echo -e "\nSave this to ~/Downloads/Nessus-*-ubuntu*_amd64.deb."
  echo -e "\nPress Enter to continue."
  read -p "" </dev/tty
done
if [ -f ~/Downloads/Nessus*.deb ] #nessus installation package found
then
  clear && echo "-- Installing Nessus"
  sudo dpkg -i ~/Downloads/Nessus-*.deb
  sudo apt-get -qq install -f
  sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Nessus\nExec=firefox https://localhost:8834\nIcon=/opt/nessus/var/nessus/www/favicon.ico\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Update\nExec=gnome-terminal --window -- bash -c '\''sudo /opt/nessus/sbin/nessuscli update --all && read -p \"Press Enter to close.\" </dev/tty'\''" > /usr/share/applications/nessus.desktop'
  sudo /etc/init.d/nessusd start
fi
#sudo rm ~/Downloads/Nessus*.deb

clear && echo "-- Installing frogger2"
sudo apt-get -qq install yersinia vlan arp-scan screen
sudo chmod +x /opt/vlan-hopping/frogger2.sh

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing Elasticsearch 6.x (natlas Database)"
  wget -q -O - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
  echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
  sudo apt-get -qq update
  sudo apt-get -qq install apt-transport-https elasticsearch
  sudo systemctl daemon-reload
  sudo systemctl enable elasticsearch.service
  sudo systemctl start elasticsearch.service

  clear && echo "-- Installing natlas"
  URL_NATLAS_AGENT=$(url_latest 'https://api.github.com/repos/natlas/natlas/releases/latest' 'natlas-agent')
  URL_NATLAS_SERVER=$(url_latest 'https://api.github.com/repos/natlas/natlas/releases/latest' 'natlas-server')
  mkdir /opt/natlas
  cd /opt/natlas/
  wget -q $URL_NATLAS_AGENT
  wget -q $URL_NATLAS_SERVER
  tar xvzf natlas-server*.tgz
  tar xvzf natlas-agent*.tgz
  sudo rm -r natlas-*.tgz
  cd /opt/natlas/natlas-server/
  sudo ./setup-server.sh
  #https://github.com/natlas/natlas/blob/main/natlas-server/README.md
  echo 'LOCAL_SUBRESOURCES=True' > /opt/natlas/natlas-server/.env

  sudo cp /opt/natlas/natlas-server/deployment/natlas-server.service /etc/systemd/system/natlas-server.service
  sudo systemctl daemon-reload
  sudo systemctl enable natlas-server.service
  sudo systemctl start natlas-server.service

  sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Natlas\nExec=firefox http://localhost:5000\nIcon=/opt/natlas/natlas-server/app/static/img/natlas-logo.png\nCategories=Application;\nActions=app1;app2;app3;\n\n[Desktop Action app1]\nName=Add User\nExec=gnome-terminal --window -- bash -c '\''printf \"\\\n\\\n\" && read -p \"Enter valid email address: \" email && clear && cd /opt/natlas/natlas-server/ && source venv/bin/activate && ./add-user.py --admin \$email && printf \"\\\n\\\n\" && read -p \"Press Enter to close.\" </dev/tty'\''\n\n[Desktop Action app2]\nName=Start Agent\nExec=gnome-terminal --window -- bash -c '\''sudo systemctl start natlas-agent'\''\n\n[Desktop Action app3]\nName=Stop Agent\nExec=gnome-terminal --window -- bash -c '\''sudo systemctl stop natlas-agent'\''" > /usr/share/applications/natlas.desktop'

  cd /opt/natlas/natlas-agent/
  sudo ./setup-agent.sh
  # https://github.com/natlas/natlas/blob/main/natlas-agent/README.md
  echo 'NATLAS_SCAN_LOCAL=True' > /opt/natlas/natlas-agent/.env

  sudo cp /opt/natlas/natlas-agent/deployment/natlas-agent.service /etc/systemd/system/natlas-agent.service
  sudo systemctl daemon-reload
  sudo systemctl disable natlas-agent.service
  #sudo systemctl start natlas-agent

  sudo chmod -R 777 /opt/natlas/
fi

########## ---------- ##########
# OSINT
########## ---------- ##########

clear && echo "-- Installing Cr3d0v3r"
cd /opt/cr3dov3r/
pipenv --bare --three install
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/cr3dov3r && if [ \$(checksudo) = 0 ]; then (pipenv run python3 Cr3d0v3r.py \"\$@\");fi)" > /usr/bin/credover'
sudo chmod +x /usr/bin/credover

clear && echo "-- Installing Hash-Buster"
cd /opt/hash-buster/
sudo make install

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing LinkedInt"
  git clone -q --depth 1 'https://github.com/vysec/linkedint' /opt/linkedint
  cd /opt/linkedint/
  pipenv --bare --two install
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/linkedint && if [ \$(checksudo) = 0 ]; then (pipenv run python2 LinkedInt.py \"\$@\");fi)" > /usr/bin/linkedint'
  sudo chmod +x /usr/bin/linkedint
fi

clear && echo "-- Installing pwndb"
cd /opt/pwndb/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/pwndb && if [ \$(checksudo) = 0 ]; then (pipenv run python3 pwndb.py \"\$@\");fi)" > /usr/bin/pwndb'
sudo chmod +x /usr/bin/pwndb

clear && echo "-- Installing pymeta"
cd /opt/pymeta/
pipenv --bare --three run python3 setup.py install --record files.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/pymeta && if [ \$(checksudo) = 0 ]; then (pipenv run python3 pymeta.py \"\$@\");fi)" > /usr/bin/pymeta'
sudo chmod +x /usr/bin/pymeta

clear && echo "-- Installing theHarvester"
cd /opt/theharvester/
pipenv --bare --three install
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/theharvester && if [ \$(checksudo) = 0 ]; then (pipenv run python3 theHarvester.py \"\$@\");fi)" > /usr/bin/theharvester'
sudo chmod +x /usr/bin/theharvester

clear && echo "-- Installing Photon"
cd /opt/photon/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/photon && if [ \$(checksudo) = 0 ]; then (pipenv run python3 photon.py \"\$@\");fi)" > /usr/bin/photon'
sudo chmod +x /usr/bin/photon

clear && echo "-- Installing Recon-ng"
cd /opt/recon-ng/
pipenv --bare --three install -r REQUIREMENTS
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/recon-ng/ && if [ \$(checksudo) = 0 ]; then (pipenv run python3 recon-ng \"\$@\");fi)" > /usr/bin/recon-ng'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/recon-ng/ && if [ \$(checksudo) = 0 ]; then (pipenv run python3 recon-cli \"\$@\");fi)" > /usr/bin/recon-cli'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/recon-ng/ && if [ \$(checksudo) = 0 ]; then (pipenv run python3 recon-web \"\$@\");fi)" > /usr/bin/recon-web'
sudo chmod +x /usr/bin/recon-*
# module dependencies
pipenv --bare install olefile pypdf3 lxml # recon/domains-contacts/metacrawler
pipenv --bare install pyaes # recon/domains-credentials/pwnedlist/account_creds
pipenv --bare install pycryptodome # recon/domains-credentials/pwnedlist/domain_creds
pipenv --bare install bs4 # recon/contacts-contacts/abc
# install all modules
bash -c 'echo -e "marketplace install /\nexit" > modules.rc'
#recon-ng -r /opt/recon-ng/modules.rc
# add api keys
bash -c 'echo -e "keys add binaryedge_api <key>\nkeys add bing_api <key>\nkeys add builtwith_api <key>\nkeys add censysio_id <key>\nkeys add censysio_secret <key>\nkeys add flickr_api <key>\nkeys add fullcontact_api <key>\nkeys add github_api <key>\nkeys add google_api <key>\nkeys add hashes_api <key>\nkeys add hibp_api <key>\nkeys add ipinfodb_api <key>\nkeys add ipstack_api <key>\nkeys add namechk_api <key>\nkeys add pwnedlist_api <key>\nkeys add pwnedlist_iv <key>\nkeys add pwnedlist_secret <key>\nkeys add shodan_api <key>\nkeys add twitter_api <key>\nkeys add twitter_secret <key>\nkeys add virustotal_api <key>\nexit" > api.rc'
#recon-ng -r /opt/recon-ng/api.rc

clear && echo "-- Installing Sudomy"
sudo apt-get -qq install phantomjs npm
sudo npm i -g wappalyzer --unsafe-perm=true
cd /opt/sudomy/
pip3 install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sudomy && if [ \$(checksudo) = 0 ]; then (bash ./sudomy \"\$@\");fi)" > /usr/bin/sudomy'
sudo chmod +x /usr/bin/sudomy

clear && echo "-- Installing httprobe (Sudomy)"
cd /opt/
mkdir httprobe
cd /opt/httprobe/
wget -q 'https://github.com/tomnomnom/httprobe/releases/download/v0.1.2/httprobe-linux-amd64-0.1.2.tgz'
tar xvzf httprobe*.tgz
sudo ln -sf /opt/httprobe/httprobe /usr/local/bin/httprobe

########## ---------- ##########
# Phishing
########## ---------- ##########

clear && echo "-- Installing evilginx"
URL_EVILGINX=$(url_latest 'https://api.github.com/repos/kgretzky/evilginx2/releases/latest' 'linux_x86')
mkdir /opt/evilginx
cd /opt/evilginx/
wget -q $URL_EVILGINX
unzip *.zip
sudo rm *.zip
sudo bash install.sh
sudo chmod +x /usr/local/bin/evilginx

########## ---------- ##########
# Wireless
########## ---------- ##########

clear && echo "-- Installing Kismet"
sudo apt-get -qq install kismet
sudo usermod -aG kismet ${USER}

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing crEAP"
  mkdir /opt/creap
  cd /opt/creap/
  wget -q 'https://raw.githubusercontent.com/Shellntel/scripts/master/crEAP.py'
  sudo chmod +x crEAP.py
  sudo apt-get -qq install mercurial screen
  cd /opt/
  hg clone 'https://bitbucket.org/secdev/scapy-com'
  sudo dpkg --ignore-depends=python-scapy -r python-scapy
  cd /opt/scapy-com/
  sudo python setup.py install --record files.txt
fi

clear && echo "-- Installing eaphammer"
cd /opt/eaphammer/
sudo ./kali-setup
pipenv --bare --three run sudo pip3 install -r pip.req
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/eaphammer/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 eaphammer \"\$@\");fi)" > /usr/bin/eaphammer'
sudo chmod +x /usr/bin/eaphammer

clear && echo "-- Installing wifite"
sudo apt-get -qq install wifite tshark

clear && echo "-- Installing hcxtools" # part wifite reqs.
cd /opt/hcxtools/
sudo make && sudo make install

clear && echo "-- Installing hcxdumptool" # part wifite reqs.
cd /opt/hcxdumptool/
sudo make && sudo make install

clear && echo "-- Installing bully" # part wifite reqs.
cd /opt/bully/src/
sudo make && sudo make install

########## ---------- ##########
# Misc
########## ---------- ##########

clear && echo "-- Installing proxmark3"
cd /opt/proxmark3/
sudo apt-get -qq install p7zip-full build-essential libreadline5 libreadline-dev libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi libstdc++-arm-none-eabi-newlib libpcsclite-dev pcscd
sudo cp -rf driver/77-mm-usb-device-blacklist.rules /etc/udev/rules.d/77-mm-usb-device-blacklist.rules
sudo udevadm control --reload-rules
sudo adduser ${USER} dialout
sudo make clean && sudo make all
sudo ln -sf /opt/proxmark3/client/proxmark3 /usr/local/bin/proxmark3

clear && echo "-- Installing Go"
sudo add-apt-repository -y ppa:longsleep/golang-backports
sudo apt-get -qq update
sudo apt-get -qq install golang-go

clear && echo "-- Installing pwndrop"
URL_PWNDROP=$(url_latest 'https://api.github.com/repos/kgretzky/pwndrop/releases/latest' 'linux-amd64')
cd /opt/
wget -q $URL_PWNDROP
tar zxvf *linux-amd64.tar.gz
sudo rm -r *linux-amd64.tar.gz
cd /opt/pwndrop/
#sudo ./pwndrop stop
sudo ./pwndrop install
#sudo ./pwndrop start
#sudo ./pwndrop status
echo -e '[pwndrop]\ndata_dir   = /usr/local/pwndrop/data\nadmin_dir  = /usr/local/pwndrop/admin\nlisten_ip  = 127.0.0.1\nhttp_port  = 80\nhttps_port = 443\n\n[setup]\nusername = "admin"\npassword = "pwndrop"\nredirect_url = ""\nsecret_path = "/pwndrop"' | sudo tee '/usr/local/pwndrop/pwndrop.ini'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=pwndrop\nExec=firefox http://localhost/pwndrop\nIcon=/opt/pwndrop/admin/favicon.png\nCategories=Application;\nActions=app1;app2;\n\n[Desktop Action app1]\nName=Start Service\nExec=gnome-terminal --window -- bash -c '\''sudo /opt/pwndrop/pwndrop start -no-autocert -no-dns && read -p \"Press Enter to close.\"'\''\n\n[Desktop Action app2]\nName=Stop Service\nExec=gnome-terminal --window -- bash -c '\''sudo /opt/pwndrop/pwndrop stop && read -p \"Press Enter to close.\"'\''" > /usr/share/applications/pwndrop.desktop'
sudo systemctl disable pwndrop.service

# moved to end of script due to time of populating the database
#clear && echo "-- Installing cve-search"
#cd /opt/cve-search/
#pipenv --bare --three install -r requirements.txt
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/cve-search/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 bin/search.py \"\$@\");fi)" > /usr/bin/cve-search'
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/cve-search/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 web/index.py \"\$@\");fi)" > /usr/bin/cve-search-webui'
#sudo chmod +x /usr/bin/cve-search*

#clear && read -r -p "Populating the cve database will take a good few hours. Do you want to do this now? [y/N] " response
#response=${response,,} # convert to lower case
#if [[ "$response" =~ ^(yes|y)$ ]]
#then
#  clear && echo "Ok... Populating the cve-search database now..."
#  pipenv --bare run sudo python ./sbin/db_mgmt_json.py -p
#  pipenv --bare run sudo python ./sbin/db_mgmt_cpe_dictionary.py
#  pipenv --bare run sudo python ./sbin/db_updater.py -c
#else
#  clear && echo "Nevermind. A script has been created in /opt/ for you to run later."
#  sudo bash -c 'echo -e "#!/bin/bash\ncd /opt/cve-search/\npipenv --bare run sudo python ./sbin/db_mgmt_json.py -p\npipenv --bare run sudo python ./sbin/db_mgmt_cpe_dictionary.py\npipenv --bare run sudo python ./sbin/db_updater.py -c" > /opt/cve-populate.sh'
#  sudo chmod +x /opt/*.sh
#fi
#sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=cve-search\nExec=firefox http://127.0.0.1:5000\nIcon=/opt/cve-search/web/static/img/favicon.ico\nCategories=Application;" > /usr/share/applications/cve-search.desktop'

########## ---------- ##########
# End
########## ---------- ##########

# Reset the Dock favourites
sudo -u ${USER} DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${RUSER_UID}/bus" dconf write /org/gnome/shell/favorite-apps "['firefox.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Terminal.desktop',  'google-chrome.desktop', 'nessus.desktop', 'BurpSuiteCommunity.desktop', 'BurpSuitePro.desktop', 'beef.desktop', 'metasploit-framework.desktop', 'covenant.desktop', 'empire.desktop', 'silenttrinity.desktop', 'merlin.desktop', 'fuzzbunch.desktop', 'bloodhound.desktop', 'bettercap.desktop', 'wireshark.desktop', 'fluxion.desktop']"

# Services fixes
sudo systemctl stop apache2.service
sudo systemctl disable apache2.service
sudo systemctl stop lighttpd.service #fluxion
sudo systemctl disable lighttpd.service #fluxion

# Cleanup apt
sudo apt-get autoremove -y
# fix empire
sudo pip3 install -r /opt/empire/setup/requirements.txt
#cd /opt/empire/
#sudo ./setup/reset.sh

# Fix VMware display
sudo sed -i 's/Before=cloud-init-local.service/Before=cloud-init-local.service\nAfter=display-manager.service/g' /lib/systemd/system/open-vm-tools.service

# Clear terminal history
cat /dev/null > /home/${USER}/.bash_history && history -c
sudo chown -R ${USER}:${USER} /home/${USER}/.bash_history

# Set permissions in /opt/
sudo chown -R ${USER}:${USER} /opt/
sudo chmod -R 777 /opt/natlas/

# Set neo4j database password to \`bloodhound\`
curl -H "Content-Type: application/json" -X POST -d '{"password":"bloodhound"}' -u neo4j:neo4j http://localhost:7474/user/neo4j/password

# Update the mlocate database
sudo updatedb

clear && echo -e "Done.\nAll modules stored in /opt/"
#echo 'View Docker images via "sudo docker images"'
#echo 'Run "msfconsole" to setup initial msf database'
#echo 'Run "cme" to setup initial CrackMapExec database'
echo -e "\n-- Notes:"
echo 'Download Burp Suite CA Certificate from http://burp/cert/'
echo 'To resolve .onion addresses (via torghost) open http://about:config/ and set network.dns.blockDotOnion to false'
echo -e "\n-- Creds:"
echo 'BeEF username and password have been set ( u:admin p:beef )'
echo 'bettercap UI username and password have been set ( u:admin p:bettercap )'
echo 'BloodHound Database username and password have been set ( u:neo4j p:bloodhound ).'
echo 'pwndrop username and password have been set ( u:admin p:pwndrop )'
echo -e "\nPress Enter to reboot."
read -p "" </dev/tty

# Clear terminal history
sudo cat /dev/null > /home/${USER}/.bash_history && history -c
sudo chown -R ${USER}:${USER} /home/${USER}/.bash_history

# Reboot
sudo reboot now