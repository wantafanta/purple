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
  local py2=$(if [[ $version == "20.04" || "21.10" || "22.04" || "22.10" ]]; then echo "false"; else echo "true"; fi)
  echo $py2
}

#if [[ $(py2_support) == "false" ]]; then
#  echo "Ubuntu 20.x no longer supports Python 2, so the below tools won't be installed. If you need them, run this script on Ubuntu 18.04 ( https://releases.ubuntu.com/18.04/ )." 1>&2
#  echo -e "\n-- crEAP\n-- Don't Kill MY Cat (DKMC)\n-- Jackit\n-- LinkedInt\n-- natlas\n-- ODAT: Oracle Database Attacking Tool\n-- PRET\n-- rdpy\n-- proxmark3\n-- Seth\n-- SimplyEmail\n-- Spoofcheck\n-- tplmap\n-- Windows Exploit Suggester\n-- zenmap\n"
#  echo "Press Enter to continue."
#  read -p "" </dev/tty
#fi

sudo bash -c 'echo -e "#!/bin/bash\nif [[ \$EUID = 0 ]]; then\n  echo \"1\"\n  exit 1\nfi\necho \"0\"" > /usr/bin/checksudo'
sudo chmod +x /usr/bin/checksudo

clear && echo "-- Lets begin ..."

# static urls (manually update)
URL_MALTEGO='https://maltego-downloads.s3.us-east-2.amazonaws.com/linux/Maltego.v4.2.19.13940.deb' # https://www.maltego.com/downloads/
URL_MONO='https://dl.winehq.org/wine/wine-mono/7.0.0/wine-mono-7.0.0-x86.msi' # https://dl.winehq.org/wine/wine-mono/
URL_OPENCL='http://registrationcenter-download.intel.com/akdlm/irc_nas/vcp/15532/l_opencl_p_18.1.0.015.tgz' # https://software.intel.com/en-us/articles/opencl-runtime-release-notes/

# function to scrape latest release from github api
url_latest() {
  local json=$(curl -s $1)
  local url=$(echo "$json" | jq -r '.assets[].browser_download_url | select(contains("'$2'"))')
  echo $url
}

# function to check application is installed
SWD=$(pwd)
[ -f "$SWD/error.log" ] && rm "$SWD/error.log"
check_app() {
  local name=$(echo $1)
  [ -f $2 ] && echo "$name is installed." || echo "$name is not installed." >> "$SWD/error.log"
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

clear && echo "-- Installing pipx"
sudo apt-get -qq install python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath

clear && echo "-- Installing pip modules"
if [[ $(py2_support) == "true" ]]; then
  sudo -H pip install -U pipenv
  clear && python3 -m pipx install service_identity # https://service-identity.readthedocs.io/en/stable/
  clear && python3 -m pipx install rdpy # https://github.com/citronneur/rdpy
fi
sudo -H pip3 install -U pipenv

clear && python3 -m pipx install pypykatz # https://github.com/skelsec/pypykatz
clear && python3 -m pipx install shodan # https://github.com/achillean/shodan-python
clear && python3 -m pipx install droopescan # https://github.com/droope/droopescan/
clear && python3 -m pipx install h8mail # https://github.com/khast3x/h8mail

#clear && echo "-- Installing poetry"
#curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python

clear && echo "Configuring TMUX"
echo 'set -g default-terminal "screen-256color"' > "/home/${USER}/.tmux.conf"
sudo chown -R ${USER}:${USER} "/home/${USER}/.tmux.conf"

clear && echo "-- Installing asciinema (terminal session recorder)" # https://github.com/asciinema/asciinema/
sudo -H pip3 install -U asciinema

clear && echo "-- Installing Firewall"
sudo apt-get -qq install gufw
sudo ufw disable
git clone --depth 1 'https://github.com/halfer/ufw-vpn' '/opt/ufw-vpn'

clear && echo "-- Installing FileZilla"
sudo apt-get -qq install filezilla

clear && echo "-- Installing FreeRDP"
sudo apt-get -qq install freerdp2-x11

clear && echo "-- Installing rdesktop"
sudo apt-get -qq install rdesktop

clear && echo "-- Installing Kazam Screencaster"
sudo apt-get -qq install kazam

clear && echo "-- Installing nmap"
sudo apt-get -qq install nmap
if [[ $(py2_support) == "true" ]]; then # not in 20.04 repo
  clear && echo "-- Installing zenmap"
  sudo apt-get -qq install zenmap
fi
sudo wget -q 'https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse' -O '/usr/share/nmap/scripts/vulners.nse'
sudo git clone -q --depth 1 'https://github.com/scipag/vulscan' '/usr/share/nmap/scripts/vulscan'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/cve.csv' -O '/usr/share/nmap/scripts/vulscan/cve.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/exploitdb.csv' -O '/usr/share/nmap/scripts/vulscan/exploitdb.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/openvas.csv' -O '/usr/share/nmap/scripts/vulscan/openvas.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/osvdb.csv' -O '/usr/share/nmap/scripts/vulscan/osvdb.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/scipvuldb.csv' -O '/usr/share/nmap/scripts/vulscan/scipvuldb.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/securityfocus.csv' -O '/usr/share/nmap/scripts/vulscan/securityfocus.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/securitytracker.csv' -O '/usr/share/nmap/scripts/vulscan/securitytracker.csv'
sudo wget -q 'http://www.computec.ch/projekte/vulscan/download/xforce.csv' -O '/usr/share/nmap/scripts/vulscan/xforce.csv'
sudo nmap --script-updatedb

clear && echo "-- Installing powershell"
sudo apt-get -qq install wget apt-transport-https software-properties-common
if [[ $(py2_support) == "false" ]]; then
  wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
else
  wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb
fi
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get -qq update
sudo apt-get -qq install -y powershell
sudo rm 'packages-microsoft-prod.deb'

clear && echo "-- Installing snaps"
sudo snap install code --classic
sudo snap install remmina
sudo snap connect remmina:avahi-observe :avahi-observe
sudo snap connect remmina:cups-control :cups-control
sudo snap connect remmina:mount-observe :mount-observe
sudo snap connect remmina:password-manager-service :password-manager-service

clear && echo "-- Cloning repositories"
cd /opt/

git clone -q --depth 1 'https://github.com/aanarchyy/bully'
git clone -q --depth 1 'https://github.com/actuated/msf-exploit-loop'
git clone -q --depth 1 'https://github.com/BC-SECURITY/empire'
git clone -q --depth 1 'https://github.com/beefproject/beef'
git clone -q --depth 1 'https://github.com/BloodHoundAD/bloodhound'
git clone -q --depth 1 'https://github.com/byt3bl33d3r/silenttrinity'
git clone -q --depth 1 'https://github.com/byt3bl33d3r/sprayingtoolkit'
git clone -q --depth 1 --recurse-submodules 'https://github.com/cobbr/covenant'
git clone -q --depth 1 'https://github.com/cve-search/cve-search'
git clone -q --depth 1 'https://github.com/D4Vinci/cr3dov3r'
git clone -q --depth 1 'https://github.com/daddycocoaman/beacongraph'
git clone -q --depth 1 'https://github.com/dafthack/mailsniper'
git clone -q --depth 1 'https://github.com/danielmiessler/seclists'
git clone -q --depth 1 'https://github.com/davidtavarez/pwndb'
git clone -q --depth 1 'https://github.com/dirkjanm/privexchange' #httpattack.py must be configured
git clone -q --depth 1 'https://github.com/evilmog/ntlmv1-multi'
git clone -q --depth 1 'https://github.com/FluxionNetwork/fluxion'
git clone -q --depth 1 'https://github.com/fox-it/bloodhound.py'
git clone -q --depth 1 'https://gitlab.com/initstring/evil-ssdp'
git clone -q --depth 1 'https://github.com/insidetrust/statistically-likely-usernames'
git clone -q --depth 1 'https://github.com/jseidl/usernamer'
git clone -q --depth 1 'https://github.com/lanmaster53/recon-ng'
git clone -q --depth 1 'https://github.com/laramies/theharvester'
git clone -q --depth 1 'https://github.com/lgandx/responder'
git clone -q --depth 1 'https://github.com/lightos/credmap'
git clone -q --depth 1 'https://github.com/m8r0wn/nullinux'
git clone -q --depth 1 --recursive 'https://github.com/mdsecresearch/lyncsniper'
git clone -q --depth 1 'https://github.com/mIcHyAmRaNe/okadminfinder3'
git clone -q --depth 1 'https://github.com/offensive-security/exploitdb'
git clone -q --depth 1 'https://github.com/Pepelux/sippts'
git clone -q --depth 1 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries' ghostpack #https://github.com/GhostPack
git clone -q --depth 1 'https://github.com/rezasp/joomscan'
git clone -q --depth 1 'https://github.com/rbsec/dnscan'
git clone -q --depth 1 'https://github.com/s0lst1c3/eaphammer'
git clone -q --depth 1 'https://github.com/s0md3v/hash-buster'
git clone -q --depth 1 'https://github.com/s0md3v/photon'
git clone -q --depth 1 'https://github.com/s0md3v/xsstrike'
git clone -q --depth 1 'https://github.com/sachinkamath/ntlmrecon'
git clone -q --depth 1 'https://github.com/threat9/routersploit'
git clone -q --depth 1 'https://github.com/trustedsec/unicorn'
git clone -q --depth 1 'https://github.com/ustayready/fireprox'
git clone -q --depth 1 'https://github.com/ZerBea/hcxtools'
git clone -q --depth 1 'https://github.com/ZerBea/hcxdumptool'
#-- PRIVILEGE ESCALATION
git clone -q --depth 1 'https://github.com/PowerShellMafia/powersploit'
git clone -q --depth 1 'https://github.com/mzet-/linux-exploit-suggester'
#-- SYSTEM AUDIT
git clone -q --depth 1 'https://github.com/diego-treitos/linux-smart-enumeration'
git clone -q --depth 1 'https://github.com/CISOfy/lynis'
#-- WEB SHELL
mkdir /opt/webshells
git clone -q --depth 1 'https://github.com/mIcHyAmRaNe/wso-webshell' '/opt/webshells/wso-webshell'
git clone -q --depth 1 'https://github.com/flozz/p0wny-shell' '/opt/webshells/p0wny-shell'
git clone -q --depth 1 'https://github.com/xl7dev/WebShell' '/opt/webshells/webshell-collection'

#-- /OPT/ SCRIPTS
bash -c 'echo -e "#!/bin/bash\nclear\nls | xargs -I{} git -C {} pull\nclear\npipx upgrade-all\nclear\nsudo airodump-ng-oui-update\nclear\nnikto -update\nclear\nwpscan --update\nclear\nsudo updatedb" > /opt/update.sh'
bash -c 'echo -e "#!/bin/bash\nsudo /usr/bin/vmhgfs-fuse .host:/ /mnt/hgfs/ -o subtype=vmhgfs-fuse,allow_other\nln -sf /mnt/hgfs/*/ ~/Desktop/" > /opt/map-shares.sh'
sudo chmod +x /opt/*.sh

#-- DESKTOP
gsettings set org.gnome.shell.extensions.desktop-icons show-home false
gsettings set org.gnome.shell.extensions.desktop-icons show-trash false
gsettings set org.gnome.desktop.privacy remember-app-usage false
bash -c "echo -e '[Desktop Entry]\nName=Link to LOLBAS\nType=Application\nExec=firefox https://lolbas-project.github.io/\nIcon=firefox\nTerminal=false' > ~/Desktop/LOLBAS.desktop"
bash -c "echo -e '[Desktop Entry]\nName=Link to GTFOBins\nType=Application\nExec=firefox https://gtfobins.github.io/\nIcon=firefox\nTerminal=false' > ~/Desktop/GTFOBins.desktop"
sudo chown -R ${USER}:${USER} "/home/${USER}/Desktop/*.desktop"

#-- BASH ALIASES
bash -c "echo -e 'alias nse=\"ls /usr/share/nmap/scripts/ | grep \"' >> /home/${USER}/.bash_aliases"
#. ~/.bashrc

#-- SYMBOLIC LINKS
sudo ln -sf /opt/evil-ssdp/evil_ssdp.py /usr/local/bin/evil-ssdp
sudo ln -sf /opt/nmapautomator/nmapAutomator.sh /usr/local/bin/nmapautomator
sudo ln -sf /opt/responder/Responder.py /usr/local/bin/responder
sudo ln -sf /opt/unicorn/unicorn.py /usr/local/bin/unicorn
sudo sed -i 's/^#!\/usr\/bin\/env python/#!\/usr\/bin\/env python2/g' /opt/usernamer/usernamer.py
sudo ln -sf /opt/usernamer/usernamer.py /usr/local/bin/usernamer

clear && echo "-- Installing Metasploit"
sudo apt-get -qq install postgresql
cd /opt/
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && sudo chmod 755 msfinstall && sudo ./msfinstall
sudo rm msfinstall
sudo wget -q 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/lib/msf/core/web_services/public/favicon.ico' -O '/opt/metasploit-framework/logo.ico'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Metasploit Framework\nExec=gnome-terminal --window -- sudo msfconsole\nIcon=/opt/metasploit-framework/logo.ico\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Web UI\nExec=kage" > /usr/share/applications/metasploit-framework.desktop'
sudo cp /opt/metasploit-framework/embedded/framework/config/database.yml.example /opt/metasploit-framework/embedded/framework/config/database.yml
sudo sed -i 's/^  password:.*/  password: msf/g' /opt/metasploit-framework/embedded/framework/config/database.yml
sudo -u postgres bash -c "psql -c \"CREATE USER metasploit_framework_development WITH PASSWORD 'msf';\""
sudo -u postgres bash -c "psql -c \"CREATE DATABASE metasploit_framework_development;\""
sudo -u postgres bash -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE metasploit_framework_development TO metasploit_framework_development;\""
mkdir "/home/${USER}/.msf4" && touch "/home/${USER}/.msf4/initial_setup_complete"

clear && echo "-- Installing Kage (Metasploit GUI)"
cd /opt/
URL_KAGE=$(url_latest 'https://api.github.com/repos/Zerx0r/Kage/releases/latest' '.AppImage')
mkdir /opt/kage
wget -q $URL_KAGE -O '/opt/kage/kage.AppImage'
sudo chmod +x /opt/kage/kage.AppImage
sudo ln -sf /opt/kage/kage.AppImage /usr/local/bin/kage
wget -q 'https://raw.githubusercontent.com/Zerx0r/Kage/master/static/kage-logo.svg' -O '/opt/kage/icon.svg'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Kage\nExec=kage\nIcon=/opt/kage/icon.svg\nCategories=Application;" > /usr/share/applications/kage.desktop'
mkdir "/home/${USER}/.local/share/appimagekit/" && touch "/home/${USER}/.local/share/appimagekit/no_desktopintegration"
check_app 'kage' '/opt/kage/kage.AppImage'

clear && echo "-- Installing searchsploit"
sed 's|path_array+=(.*)|path_array+=("/opt/exploitdb")|g' /opt/exploitdb/.searchsploit_rc > "/home/${USER}/.searchsploit_rc"
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
check_app 'searchsploit' '/opt/exploitdb/searchsploit'

clear && echo "-- Installing routersploit"
cd /opt/routersploit/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/routersploit && if [ \$(checksudo) = 0 ]; then (pipenv run python3 rsf.py \"\$@\");fi)" > /usr/bin/rsf'
sudo chmod +x /usr/bin/rsf
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/routersploit && if [ \$(checksudo) = 0 ]; then (pipenv run python3 rsf.py \"\$@\");fi)" > /usr/bin/routersploit'
sudo chmod +x /usr/bin/routersploit
check_app 'routersploit' '/opt/routersploit/rsf.py'

#clear && echo "-- Installing MongoDB (cve-search Database)"
#sudo apt-get -qq install mongodb

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
check_app 'shellter' '/opt/shellter/shellter.exe'

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing Don't Kill My Cat (DKMC)"
  git clone -q --depth 1 'https://github.com/Mr-Un1k0d3r/dkmc' '/opt/dkmc'
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
check_app 'mimikatz' '/opt/mimikatz/x64/mimikatz.exe'

clear && echo "-- Installing NtdsAudit"
URL_NTDSAUDIT=$(url_latest 'https://api.github.com/repos/Dionach/NtdsAudit/releases/latest' 'NtdsAudit.exe')
mkdir /opt/ntdsaudit
wget -q $URL_NTDSAUDIT -O '/opt/ntdsaudit/NtdsAudit.exe'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/ntdsaudit && wine NtdsAudit.exe \"\$@\")" > /usr/bin/ntdsaudit'
sudo chmod +x /usr/bin/ntdsaudit
check_app 'ntdsaudit' '/opt/ntdsaudit/NtdsAudit.exe'

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
check_app 'ntdsdumpex' '/opt/ntdsdumpex/NTDSDumpEx.exe'

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
check_app 'merlin' '/opt/merlin/merlinServer-Linux-x64'

if [[ $(py2_support) == "true" ]]; then
  clear && echo "Installing Windows Exploit Suggester"
  git clone -q --depth 1 'https://github.com/GDSSecurity/windows-exploit-suggester' '/opt/windows-exploit-suggester'
  sudo bash -c 'echo -e "#!/bin/bash\n(python2 /opt/windows-exploit-suggester/windows-exploit-suggester.py \"\$@\")" > /usr/bin/windows-exploit-suggester'
  sudo chmod +x /usr/bin/windows-exploit-suggester
fi

clear && python3 -m pipx install wesng # https://github.com/bitsadmin/wesng

clear && echo "-- Installing DNScan"
cd /opt/dnscan/
pipenv --bare --three install
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/dnscan/ && if [ \$(checksudo) = 0 ]; then (pipenv run python3 dnscan.py \"\$@\");fi)" > /usr/bin/dnscan'
sudo chmod +x /usr/bin/dnscan
check_app 'dnscan' '/opt/dnscan/dnscan.py'

clear && echo "-- Installing DeathStar"
clear && python3 -m pipx install deathstar-empire

clear && clear && echo "-- Installing Empire"
#echo
#echo "Empire PowerShell modules will require preobfuscation. When prompted, enter \`y\` twice."
#echo
#echo "Press Enter to continue."
#read -p "" </dev/tty
cd /opt/empire/
sudo apt-get -qq install python3-m2crypto
sudo ./setup/install.sh
sudo pip3 install pyparsing
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/empire && sudo ./ps-empire \"\$@\")" > /usr/bin/empire'
sudo chmod +x /usr/bin/empire
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Empire\nExec=gnome-terminal --window -- empire client\nIcon=/opt/empire/empire/server/data/misc/apptemplateResources/icon/stormtrooper.icns\nCategories=Application;\nActions=app1;app2;app3;\n\n[Desktop Action app1]\nName=Start Team Server\nExec=gnome-terminal --window -- empire server\n[Desktop Action app2]\nName=Starkiller GUI\nExec=starkiller\n[Desktop Action app3]\nName=DeathStar\nExec=gnome-terminal --window -- bash -c '\''read -p \"Enter REST API username: \" user && read -p \"Enter REST API password: \" pass && deathstar -u \$user -p \$pass && read -p \"Press Enter to close.\" </dev/tty'\''" > /usr/share/applications/empire.desktop'
bash -c 'echo -e "preobfuscate\nexit" > /opt/empire/obf.rc'
empire -r /opt/empire/obf.rc
sudo rm /opt/empire/obf.rc
check_app 'empire' '/opt/empire/ps-empire'

clear && echo "-- Installing Starkiller (Empire GUI)"
cd /opt/
URL_STARKILLER=$(url_latest 'https://api.github.com/repos/BC-SECURITY/Starkiller/releases/latest' '.AppImage')
mkdir /opt/starkiller
wget -q $URL_STARKILLER -O '/opt/starkiller/starkiller.AppImage'
sudo chmod +x /opt/starkiller/starkiller.AppImage
sudo ln -sf /opt/starkiller/starkiller.AppImage /usr/local/bin/starkiller
wget -q 'https://raw.githubusercontent.com/BC-SECURITY/Starkiller/master/src/assets/icon.png' -O '/opt/starkiller/icon.png'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Starkiller\nExec=starkiller\nIcon=/opt/starkiller/icon.png\nCategories=Application;" > /usr/share/applications/starkiller.desktop'
check_app 'starkiller' '/opt/starkiller/starkiller.AppImage'

clear && echo "-- Installing Dotnet Core 3.1 (Covenant)"
cd /opt/
wget -q 'https://download.visualstudio.microsoft.com/download/pr/8db2b522-7fa2-4903-97ec-d6d04d297a01/f467006b9098c2de256e40d2e2f36fea/dotnet-sdk-3.1.301-linux-x64.tar.gz'
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
check_app 'covenant' '/opt/covenant/Covenant/Covenant.cs'

clear && python3 -m pipx install mitm6 # https://github.com/fox-it/mitm6/
sudo ln -sf "/home/${USER}/.local/bin/mitm6" /usr/local/bin/
check_app 'mitm6' "/home/${USER}/.local/bin/mitm6"
clear && python3 -m pipx install impacket # https://github.com/SecureAuthCorp/impacket - https://www.secureauth.com/labs/open-source-tools/impacket
sudo ln -sf "/home/${USER}/.local/bin/"*.py /usr/local/bin/
clear && python3 -m pipx install crackmapexec # https://github.com/byt3bl33d3r/crackmapexec/
sudo ln -sf "/home/${USER}/.local/bin/cme" /usr/local/bin/
sudo ln -sf "/home/${USER}/.local/bin/cmedb" /usr/local/bin/
sudo ln -sf "/home/${USER}/.local/bin/crackmapexec" /usr/local/bin/
check_app 'crackmapexec' "/home/${USER}/.local/bin/cme"

mkdir "/home/${USER}/.local/pipx/venvs/crackmapexec/lib/python3.8/site-packages/cme/data/powersploit/"
mkdir "/home/${USER}/.local/pipx/venvs/crackmapexec/lib/python3.8/site-packages/cme/data/powersploit/Exfiltration/"
cp "/opt/empire/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1" "/home/${USER}/.local/pipx/venvs/crackmapexec/lib/python3.8/site-packages/cme/data/powersploit/Exfiltration/Invoke-Mimikatz.ps1"

clear && python3 -m pipx install activereign # https://github.com/m8r0wn/activereign
clear && python3 -m pipx inject activereign impacket
clear && python3 -m pipx install adidnsdump # https://github.com/dirkjanm/adidnsdump
# sudo ~/.local/bin/

clear && echo "-- Installing evil-winrm"
sudo gem install evil-winrm # https://github.com/Hackplayers/evil-winrm

clear && echo "-- Installing BloodHound"
URL_BLOODHOUND=$(url_latest 'https://api.github.com/repos/BloodHoundAD/BloodHound/releases/latest' 'linux-x64')
cd /opt/
wget -q $URL_BLOODHOUND
unzip BloodHound-linux-x64.zip
sudo rm BloodHound*.zip
mv BloodHound-linux-x64/ bloodhound-bin/
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=BloodHound\nExec=\"/opt/bloodhound-bin/BloodHound\"\nIcon=/opt/bloodhound/src/img/icon.ico\nCategories=Application;" > /usr/share/applications/bloodhound.desktop'
check_app 'bloodhound' '/opt/bloodhound-bin/BloodHound'

clear && echo "-- Installing Neo4j (BloodHound Database)"
cd /opt/
sudo apt-get remove -y java-common
sudo apt-get -qq install openjdk-11-jre-headless
wget -q --no-check-certificate -O - 'https://debian.neo4j.com/neotechnology.gpg.key' | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.0' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
sudo apt-get -qq update
sudo apt-get -qq install neo4j
#sudo systemctl stop neo4j.service
#sudo sed -i 's/#dbms.security.auth_enabled=false/dbms.security.auth_enabled=false/g' /etc/neo4j/neo4j.conf
#sudo systemctl start neo4j.service
sudo systemctl enable neo4j.service

clear && echo "-- Installing cypher-shell"
URL_CYPHERSHELL=$(url_latest 'https://api.github.com/repos/neo4j/cypher-shell/releases/latest' '.deb')
cd /opt/
wget -q $URL_CYPHERSHELL
sudo apt-get -qq install ./cypher-shell_*.deb
sudo rm cypher-shell_*.deb
check_app 'cypher-shell' '/usr/bin/cypher-shell'

clear && echo "-- Installing BloodHound Custom Queries"
mkdir "/home/${USER}/.config/bloodhound"
curl 'https://raw.githubusercontent.com/hausec/Bloodhound-Custom-Queries/master/customqueries.json' > "/home/${USER}/.config/bloodhound/customqueries.json"

clear && echo "-- Installing bloodhound.py"
cd /opt/bloodhound.py/
pipenv --bare --three run python3 setup.py install --record files.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/bloodhound.py/ && if [ \$(checksudo) = 0 ]; then (pipenv run python3 bloodhound.py \"\$@\");fi)" > /usr/bin/bloodhound.py'
sudo chmod +x /usr/bin/bloodhound.py
check_app 'bloodhound.py' '/usr/bin/bloodhound.py'

clear && python3 -m pipx install aclpwn # https://github.com/fox-it/aclpwn.py
clear && python3 -m pipx inject aclpwn neo4j-driver

clear && echo "-- Installing Scout Suite"
git clone -q --depth 1 'https://github.com/nccgroup/scoutsuite' '/opt/scoutsuite'
cd /opt/scoutsuite/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/scoutsuite && if [ \$(checksudo) = 0 ]; then (pipenv run python3 scout.py \"\$@\");fi)" > /usr/bin/scoutsuite'
sudo chmod +x /usr/bin/scoutsuite
check_app 'scoutsuite.py' '/opt/scoutsuite/scout.py'

clear && echo "-- Installing ROADtools"
clear && python3 -m pipx install roadrecon # https://github.com/dirkjanm/roadtools
clear && python3 -m pipx inject roadrecon neo4j-driver

clear && echo "-- Installing Azure CLI"
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash # https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-linux

clear && echo "-- Installing AWS CLI" # https://awscli.amazonaws.com/v2/documentation/api/latest/index.html
cd /opt/
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" # https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html
unzip awscliv2.zip
sudo ./aws/install
sudo rm awscliv2.zip

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
check_app 'fireprox' '/opt/fireprox/fire.py'

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing SimplyEmail"
  git clone -q --depth 1 'https://github.com/SimplySecurity/simplyemail' '/opt/simplyemail'
  sudo apt-get -qq install python-lxml grep antiword odt2txt python-dev libxml2-dev libxslt1-dev
  cd /opt/simplyemail/
  pipenv --bare --two install -r setup/req*.txt
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/simplyemail && if [ \$(checksudo) = 0 ]; then (pipenv run python2.7 SimplyEmail.py \"\$@\");fi)" > /usr/bin/simplyemail'
  sudo chmod +x /usr/bin/simplyemail

  clear && echo "-- Installing JackIt"
  git clone -q --depth 1 'https://github.com/insecurityofthings/jackit' '/opt/jackit'
  cd /opt/jackit/
  pipenv --bare --two run sudo python2 setup.py install --record files.txt
  sudo rm /usr/local/bin/jackit
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/jackit/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo bin/jackit \"\$@\");fi)" > /usr/bin/jackit'
  sudo chmod +x /usr/bin/jackit

  clear && echo "-- Installing spoofcheck"
  git clone -q --depth 1 'https://github.com/BishopFox/spoofcheck' '/opt/spoofcheck'
  cd /opt/spoofcheck/
  pipenv --bare --two run sudo pip2 install -r requirements.txt
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/spoofcheck/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python2 spoofcheck.py \"\$@\");fi)" > /usr/bin/spoofcheck'
  sudo chmod +x /usr/bin/spoofcheck
fi

clear && echo "-- Installing Docker"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get -qq update && sudo apt-get -qq install docker-ce docker-ce-cli containerd.io

clear && echo "-- Installing docker-compose"
URL_DOCKERCOMPOSE=$(url_latest 'https://api.github.com/repos/docker/compose/releases/latest' 'docker-compose-linux-x86_64')
sudo wget -q $URL_DOCKERCOMPOSE -O /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
check_app 'docker-compose' '/usr/local/bin/docker-compose'

clear && echo "-- Installing Camradar (docker)"
sudo docker pull ullaakut/cameradar
sudo bash -c 'echo -e "#!/bin/bash\n(sudo docker run -t ullaakut/cameradar \"\$@\")" > /usr/local/bin/cameradar' && sudo chmod +x /usr/local/bin/cameradar

clear && echo "-- Installing Pwndoc (docker)"
git clone -q --depth 1 'https://github.com/pwndoc/pwndoc' '/opt/pwndoc'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Pwndoc\nExec=firefox https://localhost:8443\nIcon=/opt/pwndoc/frontend/public/favicon.ico\nCategories=Application;\nActions=app1;app2;\n\n[Desktop Action app1]\nName=Start Server\nExec=gnome-terminal --window -- bash -c '\''cd /opt/pwndoc && sudo docker-compose start && read -p \"Press Enter to close.\"'\''\n\n[Desktop Action app2]\nName=Stop Server\nExec=gnome-terminal --window -- bash -c '\''cd /opt/pwndoc && sudo docker-compose stop && read -p \"Press Enter to close.\"'\''" > /usr/share/applications/pwndoc.desktop'
cd /opt/pwndoc
sudo docker-compose up -d --build
sudo docker-compose stop
sudo docker update --restart no pwndoc-backend
sudo docker update --restart no pwndoc-frontend
docker update --restart no mongo-pwndoc
# admin / admin

clear && echo "-- Installing credmap"
cd /opt/credmap/
sudo chmod +x credmap.py
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/credmap/ && python credmap.py \"\$@\")" > /usr/bin/credmap'
sudo chmod +x /usr/bin/credmap
check_app 'credmap' '/opt/credmap/credmap.py'

clear && echo "-- Installing Google Chrome (Stable)" #for gowitness
wget -q -O - 'https://dl-ssl.google.com/linux/linux_signing_key.pub' | sudo apt-key add -
echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt-get -qq update
sudo apt-get -qq install google-chrome-stable

clear && echo "-- Installing gowitness"
URL_GOWITNESS=$(url_latest 'https://api.github.com/repos/sensepost/gowitness/releases/latest' 'linux-amd64')
mkdir /opt/gowitness
cd /opt/gowitness
wget -q $URL_GOWITNESS -O 'gowitness-linux-amd64'
sudo chmod +x gowitness-linux-amd64
sudo ln -sf /opt/gowitness/gowitness-linux-amd64 /usr/local/bin/gowitness
check_app 'gowitness' '/opt/gowitness/gowitness-linux-amd64'

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
sudo ln -sf /opt/aquatone/aquatone /usr/local/bin/aquatone
check_app 'aquatone' '/opt/aquatone/aquatone'

clear && echo "-- Installing ruler"
URL_RULER=$(url_latest 'https://api.github.com/repos/sensepost/ruler/releases/latest' 'linux64')
mkdir /opt/ruler
cd /opt/ruler/
wget -q $URL_RULER
sudo chmod +x ruler-linux64
sudo ln -sf /opt/ruler/ruler-linux64 /usr/local/bin/ruler
check_app 'ruler' '/opt/ruler/ruler-linux64'

clear && echo "-- Installing SilentTrinity"
cd /opt/silenttrinity/
wget -q 'https://user-images.githubusercontent.com/5151193/45964397-e462e280-bfe2-11e8-88a7-69212e0f0355.png' -O '/opt/silenttrinity/logo.png'
pipenv --bare --three run sudo pip3 install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/silenttrinity/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 st.py \"\$@\");fi)" > /usr/bin/silenttrinity'
sudo chmod +x /usr/bin/silenttrinity
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=SilentTrinity\nExec=gnome-terminal --window -- silenttrinity client\nIcon=/opt/silenttrinity/logo.png\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Start Teamserver\nExec=gnome-terminal --window -- bash -c '\''printf \"\\\n\\\n\" && nmcli d show | grep .ADDRESS && printf \"\\\n\\\n\" && read -p \"Enter the IP address to use: \" ip &&  read -p \"Enter the password to use: \" pass && clear && silenttrinity teamserver \$ip \$pass'\''\n" > /usr/share/applications/silenttrinity.desktop'
check_app 'silenttrinity' '/opt/silenttrinity/st.py'

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
check_app 'dbeaver' '/usr/bin/dbeaver'

clear && echo "-- Installing Sqlectron"
URL_SQLECTRON=$(url_latest 'https://api.github.com/repos/sqlectron/sqlectron-gui/releases/latest' 'amd64')
cd /opt/
wget -q $URL_SQLECTRON
sudo apt-get -qq install ./sqlectron*.deb
sudo rm sqlectron*.deb
check_app 'dbeaver' '/usr/bin/sqlectron'

clear && echo "-- Installing nullinux"
cd /opt/nullinux/
sudo apt-get -qq install smbclient
sudo bash setup.sh
check_app 'nullinux' '/usr/local/bin/nullinux'

clear && echo "-- Installing enumdb"
git clone --depth 1 'https://github.com/m8r0wn/enumdb' '/opt/enumdb'
cd /opt/enumdb/
sudo python3 setup.py install
check_app 'enumdb' '/usr/local/bin/enumdb'

clear && echo "-- Installing File Cracks"
sudo apt-get -qq install fcrackzip

clear && echo "-- Installing NFS Utils"
sudo apt-get -qq install nfs-common

clear && echo "-- Installing GPS Utils"
sudo apt-get -qq install gpsd gpsd-clients

clear && echo "-- Installing navi" # will be good to use with some pentest .cheat files
git clone -q --depth 1 'https://github.com/junegunn/fzf' '/opt/fzf'
/opt/fzf/install --all
git clone -q --depth 1 'https://github.com/denisidoro/navi' '/opt/navi'
/opt/navi/scripts/install
sudo mv "/home/${USER}/.cargo/bin/navi" /usr/local/bin/navi
bash -c "echo -e 'eval "$(navi widget bash)"' >> /home/${USER}/.bashrc"
check_app 'navi' '/usr/local/bin/navi'

clear && echo "-- Installing bruteforce-salted-openssl"
sudo apt-get -qq install autoconf
git clone -q --depth 1 'https://github.com/glv2/bruteforce-salted-openssl' '/opt/bruteforce-salted-openssl'
cd /opt/bruteforce-salted-openssl
bash autogen.sh
./configure
make
sudo make install
check_app 'bruteforce-salted-openssl' '/usr/local/bin/bruteforce-salted-openssl'

########## ---------- ##########
# Brute-force
########## ---------- ##########

clear && echo "-- Installing patator"
#git clone -q --depth 1 'https://github.com/lanjelot/patator' '/opt/patator'
#cd /opt/patator/
sudo apt-get -qq install libcurl4-openssl-dev python3-dev libssl-dev # pycurl
sudo apt-get -qq install ldap-utils # ldapsearch
sudo apt-get -qq install libmysqlclient-dev # mysqlclient-python
sudo apt-get -qq install ike-scan unzip default-jdk
sudo apt-get -qq install libsqlite3-dev libsqlcipher-dev # pysqlcipher
#pipenv --bare --three run sudo python setup.py install --record files.txt
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/patator/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo patator.py \"\$@\");fi)" > /usr/bin/patator'
#sudo chmod +x /usr/bin/patator
python3 -m pipx install patator
check_app 'patator' "/home/${USER}/.local/bin/patator.py"

sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/ftp_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/ssh_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/telnet_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/smtp_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/smtp_vrfy
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/smtp_rcpt
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/finger_lookup
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/http_fuzz
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/rdp_gateway
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/ajp_fuzz
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/pop_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/pop_passd
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/imap_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/ldap_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/dcom_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/smb_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/smb_lookupsid
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/rlogin_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/vmauthd_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/mssql_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/oracle_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/mysql_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/mysql_query
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/rdp_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/pgsql_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/vnc_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/dns_forward
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/dns_reverse
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/snmp_login
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/ike_enum
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/unzip_pass
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/keystore_pass
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/sqlcipher_pass
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/umbraco_crack
sudo ln -sf "/home/${USER}/.local/bin/patator.py" /usr/bin/tcp_fuzz

clear && echo "-- Installing iker" # https://labs.portcullis.co.uk/download/iker_v1.1.tar
curl 'https://raw.githubusercontent.com/Zamanry/iker/master/iker.py' | sudo tee /usr/local/bin/iker.py
sudo chmod +x /usr/local/bin/iker.py
check_app 'iker' '/usr/local/bin/iker.py'

clear && echo "-- Installing kerbrute"
URL_KERBRUTE=$(url_latest 'https://api.github.com/repos/ropnop/kerbrute/releases/latest' 'linux_amd64')
mkdir /opt/kerbrute
cd /opt/kerbrute/
wget -q $URL_KERBRUTE
sudo chmod +x kerbrute_linux_amd64
sudo ln -sf /opt/kerbrute/kerbrute_linux_amd64 /usr/local/bin/kerbrute
check_app 'kerbrute' '/opt/kerbrute/kerbrute_linux_amd64'

########## ---------- ##########
# VoIP
########## ---------- ##########

clear && echo "-- Installing sippts"
sudo cpan -i IO:Socket:Timeout NetAddr:IP String:HexConvert Net:Pcap Net::Address::IP::Local DBI DBD::SQLite
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipscan.pl \"\$@\")" > /usr/bin/sipscan'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipexten.pl \"\$@\")" > /usr/bin/sipexten'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipcracker.pl \"\$@\")" > /usr/bin/sipcracker'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipinvite.pl \"\$@\")" > /usr/bin/sipinvite'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipsniff.pl \"\$@\")" > /usr/bin/sipsniff'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipspy.pl \"\$@\")" > /usr/bin/sipspy'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipdigestleak.pl \"\$@\")" > /usr/bin/sipdigestleak'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sippts/ && perl sipreport.pl \"\$@\")" > /usr/bin/sipreport'
sudo chmod +x /usr/bin/sip*
check_app 'sippts' '/opt/sippts/sipscan.pl'

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
check_app 'fluxion' '/usr/bin/fluxion'

#clear && echo "-- Installing BeaconGraph"
#cd /opt/beacongraph/
#pipenv --bare --three install -r requirements.txt
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/beacongraph/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 BeaconGraph.py \"\$@\");fi)" > /usr/bin/beacongraph'
#sudo chmod +x /usr/bin/beacongraph

########## ---------- ##########
# Password Cracking
########## ---------- ##########

clear && echo "-- Installing John the Ripper"
sudo apt-get -qq install john

clear && echo "-- Installing hashcat"
URL_HASHCAT=$(url_latest 'https://api.github.com/repos/hashcat/hashcat/releases/latest' 'hashcat')
cd /opt/
wget -q $URL_HASHCAT
7zr x hashcat-*.7z
sudo rm hashcat-*.7z
mv hashcat-*/ hashcat/
sudo ln -sf /opt/hashcat/hashcat.bin /usr/local/bin/hashcat
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
check_app 'hashcat' '/opt/hashcat/hashcat.bin'

clear && echo "-- Installing hashcat-utils"
URL_HASHCAT_UTILS=$(url_latest 'https://api.github.com/repos/hashcat/hashcat-utils/releases/latest' 'hashcat-utils')
cd /opt/
wget -q $URL_HASHCAT_UTILS
7zr x hashcat-utils-*.7z
sudo rm hashcat-utils-*.7z
mv hashcat-utils-*/ hashcat-utils/
check_app 'hashcat-utils' '/opt/hashcat-utils/bin/cap2hccapx.bin'

########## ---------- ##########
# Web
########## ---------- ##########

#trap '' INT
# burp suite community or pro
#if [ ! -f ~/Downloads/burpsuite_pro_linux*.sh ] #burp professional installation script not found - ask if required
#then
#  clear
#  echo "Burp Suite Professional installation script not found."
#  echo -e "\nDownload \`burpsuite_pro_linux*.sh\` from: https://portswigger.net/users/youraccount"
#  echo -e "\nSave this to ~/Downloads/burpsuite_pro_linux*.sh, otherwise the Community Edition will be installed."
#  echo -e "\nPress Enter to continue (or skip)."
#  read -p "" </dev/tty
#  if [ ! -f ~/Downloads/burpsuite_pro_linux*.sh ] #burp professional not required, install burp community edition
#  then
#    clear && echo "-- Installing Burp Suite Community Edition"
#    curl 'https://portswigger.net/burp/releases/download?product=community&type=linux' -o /opt/install.sh && sudo chmod +x /opt/install.sh
#    sudo /opt/install.sh -dir /opt/burpsuitecommunity -overwrite -q
#    sudo rm /opt/install.sh
#    sudo mv /usr/share/applications/*BurpSuiteCommunity.desktop /usr/share/applications/BurpSuiteCommunity.desktop
#    #sudo bash -c "echo -e 'StartupWMClass=com-install4j-runtime-launcher-UnixLauncher' >> '/usr/share/applications/BurpSuiteCommunity.desktop'"
#  fi
#fi
#if [ -f ~/Downloads/burpsuite_pro_linux*.sh ] #burp professional installation script found, install burp professional
#then
  clear && echo "-- Installing Burp Suite Professional Edition"
  curl 'https://portswigger.net/burp/releases/download?product=pro&type=Linux' -o /opt/install.sh && sudo chmod +x /opt/install.sh
  sudo sudo /opt/install.sh -dir /opt/burpsuitepro -overwrite -q
  sudo rm /opt/install.sh
  sudo rename -d "s/(?:.*)BurpSuitePro.desktop/BurpSuitePro.desktop/" /usr/share/applications/*BurpSuitePro.desktop
  sudo bash -c "echo -e '\nActions=app1;\n\n[Desktop Action app1]\nName=Start Collaborator Server\nExec=gnome-terminal --window -- bash -c '\''cd /opt/burpsuitepro/ && sudo java -Xms10m -Xmx200m -XX:GCTimeRatio=19 -jar burpsuite_pro.jar --collaborator-server --collaborator-config=collaborator.config'\''' >> '/usr/share/applications/BurpSuitePro.desktop'"
  sudo touch /opt/burpsuitepro/collaborator.config
  # https://portswigger.net/burp/documentation/collaborator/deploying#collaborator-configuration-file-format
#fi
#trap - INT
check_app 'burpsuitepro' '/opt/burpsuitepro/BurpSuitePro'
# download jython (burp extensions)
wget -q 'http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.0/jython-standalone-2.7.0.jar' -O "/home/${USER}/Documents/jython-standalone-2.7.0.jar"
check_app 'burpsuite extension: jython' "/home/${USER}/Documents/jython-standalone-2.7.0.jar"

clear && echo "-- Installing smuggler"
git clone --depth 1 'https://github.com/defparam/smuggler' '/opt/smuggler'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/smuggler && if [ \$(checksudo) = 0 ]; then (python3 ./smuggler.py \"\$@\");fi)" > /usr/bin/smuggler'
sudo chmod +x /usr/bin/smuggler
check_app 'smuggler' '/opt/smuggler/smuggler.py'

clear && echo "-- Installing Swagger UI"
sudo apt-get -qq install npm
git clone -q --depth 1 'https://github.com/swagger-api/swagger-ui' '/opt/swagger-ui'
cd /opt/swagger-ui/
npm install
#npm run build
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/swagger-ui && if [ \$(checksudo) = 0 ]; then (npm start \"\$@\");fi)" > /usr/bin/swagger-ui'
#sudo chmod +x /usr/bin/swagger-ui
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/swagger-ui && if [ \$(checksudo) = 0 ]; then (npm run dev \"\$@\");fi)" > /usr/bin/swagger-ui-dev'
#sudo chmod +x /usr/bin/swagger-ui-dev
wget -q 'https://upload.wikimedia.org/wikipedia/commons/a/ab/Swagger-logo.png' -O '/opt/swagger-ui/logo.png'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Swagger UI\nExec=firefox /opt/swagger-ui/dist/index.html\nIcon=/opt/swagger-ui/logo.png\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Start local dev build\nExec=gnome-terminal --window -- bash -c '\''cd /opt/swagger-ui && npm run dev'\''" > /usr/share/applications/swagger-ui.desktop'
# put local yaml/json files in dev-helpers folder
check_app 'swagger ui' '/opt/swagger-ui/dist/index.html'

clear && echo "-- Installing Swagger Editor"
git clone --depth 1 'https://github.com/swagger-api/swagger-editor' '/opt/swagger-editor'
cd /opt/swagger-editor/
#npm install
#npm run build
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/swagger-editor && if [ \$(checksudo) = 0 ]; then (npm start \"\$@\");fi)" > /usr/bin/swagger-editor'
#sudo chmod +x /usr/bin/swagger-editor
wget -q 'https://upload.wikimedia.org/wikipedia/commons/a/ab/Swagger-logo.png' -O '/opt/swagger-editor/logo.png'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Swagger Editor\nExec=firefox /opt/swagger-editor/index.html\nIcon=/opt/swagger-ui/logo.png\nCategories=Application;" > /usr/share/applications/swagger-editor.desktop'
check_app 'swagger editor' '/opt/swagger-editor/index.html'

clear && echo "-- Installing Swagger-EZ"
git clone --depth 1 'https://github.com/RhinoSecurityLabs/swagger-ez' '/opt/swagger-ez'
wget -q 'https://avatars0.githubusercontent.com/u/11430746' -O '/opt/swagger-ez/logo.png'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Swagger-EZ\nExec=firefox /opt/swagger-ez/index.html\nIcon=/opt/swagger-ez/logo.png\nCategories=Application;" > /usr/share/applications/swagger-ez.desktop'
check_app 'swagger-ez' '/opt/swagger-ez/index.html'

clear && echo "-- Installing Postman"
cd /opt/
curl 'https://dl.pstmn.io/download/latest/linux64' -o '/opt/postman.tar.gz'
tar xvf postman.tar.gz
sudo rm postman.tar.gz
mv /opt/Postman /opt/postman
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Postman\nExec=/opt/postman/Postman\nIcon=/opt/postman/app/resources/app/assets/icon.png\nCategories=Application;" > /usr/share/applications/postman.desktop'
check_app 'postman' '/opt/postman/Postman'

clear && echo "-- Installing CyberChef"
URL_CYBERCHEF=$(url_latest 'https://api.github.com/repos/gchq/cyberchef/releases/latest' 'CyberChef_')
mkdir /opt/cyberchef/
cd /opt/cyberchef/
wget -q $URL_CYBERCHEF
unzip CyberChef_*
sudo rm CyberChef_*.zip
mv CyberChef*.html CyberChef.html
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=CyberChef\nExec=firefox /opt/cyberchef/CyberChef.html\nIcon=/opt/cyberchef/images/cyberchef-128x128.png\nCategories=Application;" > /usr/share/applications/cyberchef.desktop'
check_app 'cyberchef' '/opt/cyberchef/CyberChef.html'

clear && echo "-- Installing sqlmap"
git clone -q --depth 1 'https://github.com/sqlmapproject/sqlmap' '/opt/sqlmap'
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sqlmap/ && python3 sqlmap.py \"\$@\")" > /usr/bin/sqlmap'
sudo chmod +x /usr/bin/sqlmap
check_app 'sqlmap' '/opt/sqlmap/sqlmap.py'

clear && echo "-- Installing jsql-injection"
URL_JSQL=$(url_latest 'https://api.github.com/repos/ron190/jsql-injection/releases/tags/v0.83' '.jar') # https://github.com/ron190/jsql-injection/releases/
mkdir /opt/jsql-injection/
wget -q $URL_JSQL -O '/opt/jsql-injection/jsql-injection.jar'
wget -q 'https://github.com/ron190/jsql-injection/raw/master/view/src/main/resources/swing/images/software/bug128.png' -O '/opt/jsql-injection/logo.png'
sudo bash -c 'echo -e "#!/bin/bash\n(java -jar /opt/jsql-injection/jsql-injection.jar \"\$@\")" > /usr/bin/jsql'
sudo chmod +x /usr/bin/jsql
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=jSQL Injection\nExec=gnome-terminal --window -- jsql\nIcon=/opt/jsql-injection/logo.png\nCategories=Application;" > /usr/share/applications/jsql.desktop'
check_app 'jsql-injection' '/opt/jsql-injection/jsql-injection.jar'

clear && echo "-- Installing JD-GUI"
URL_JDGUI=$(url_latest 'https://api.github.com/repos/java-decompiler/jd-gui/releases/latest' '.deb')
cd /opt/
wget -q $URL_JDGUI
sudo apt-get -qq install ./jd-gui-*.deb
sudo rm jd-gui-*.deb
check_app 'jd-gui' '/opt/jd-gui/jd-gui.jar'

clear && echo "-- Installing Whatwaf"
git clone -q --depth 1 'https://github.com/Ekultek/whatwaf' '/opt/whatwaf'
cd /opt/whatwaf/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/whatwaf && if [ \$(checksudo) = 0 ]; then (pipenv run python3 whatwaf \"\$@\");fi)" > /usr/bin/whatwaf'
sudo chmod +x /usr/bin/whatwaf
check_app 'whatwaf' '/opt/whatwaf/whatwaf'

clear && echo "-- Installing nikto"
sudo apt-get -qq install nikto
nikto -update

clear && echo "-- Installing ffuf"
URL_FFUF=$(url_latest 'https://api.github.com/repos/ffuf/ffuf/releases/latest' 'linux_amd64.tar.gz')
mkdir /opt/ffuf/
cd /opt/ffuf/
wget -q $URL_FFUF
tar xvf *linux_amd64.tar.gz
chmod +x ffuf
sudo ln -sf /opt/ffuf/ffuf /usr/local/bin/ffuf
check_app 'ffuf' '/opt/ffuf/ffuf'

clear && echo "-- Installing wfuzz"
python3 -m pipx install wfuzz # https://github.com/xmendez/wfuzz

clear && echo "-- Installing testssl.sh"
git clone -q --depth 1 'https://github.com/drwetter/testssl.sh' '/opt/testssl.sh'
sudo bash -c 'echo -e "#!/bin/bash\n(/opt/testssl.sh/testssl.sh \"\$@\")" > /usr/bin/testssl.sh'
sudo chmod +x /usr/bin/testssl.sh
check_app 'testssl.sh' '/opt/testssl.sh/testssl.sh'

clear && echo "-- Installing Gobuster"
URL_GOBUSTER=$(url_latest 'https://api.github.com/repos/OJ/gobuster/releases/latest' 'gobuster-linux-amd64.7z')
mkdir /opt/gobuster
cd /opt/gobuster/
wget -q $URL_GOBUSTER
7z x gobuster-linux-amd64.7z
mv gobuster-linux-amd64/gobuster .
sudo rm gobuster-linux-amd64.7z
sudo rm gobuster-linux-amd64
sudo chmod +x gobuster
sudo ln -sf /opt/gobuster/gobuster /usr/local/bin/gobuster
check_app 'gobuster' '/opt/gobuster/gobuster'

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
sudo ln -sf /opt/dirble/dirble /usr/local/bin/dirble
check_app 'dirble' '/opt/dirble/dirble'

clear && echo "-- Installing recursebuster"
URL_RECURSEBUSTER=$(url_latest 'https://api.github.com/repos/C-Sto/recursebuster/releases/latest' 'recursebuster_elf')
URL_RECURSEBUSTER_README='https://raw.githubusercontent.com/C-Sto/recursebuster/master/README.md'
mkdir /opt/recursebuster
cd /opt/recursebuster/
wget -q $URL_RECURSEBUSTER
wget -q $URL_RECURSEBUSTER_README
sudo chmod +x recursebuster_elf
sudo ln -sf /opt/recursebuster/recursebuster_elf /usr/local/bin/recursebuster
check_app 'recursebuster' '/opt/recursebuster/recursebuster_elf'

clear && echo "-- Installing okadminfinder3"
cd /opt/okadminfinder3/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/okadminfinder3 && if [ \$(checksudo) = 0 ]; then (pipenv run python3 okadminfinder.py \"\$@\");fi)" > /usr/bin/okadminfinder3'
sudo chmod +x /usr/bin/okadminfinder3
check_app 'okadminfinder3' '/opt/okadminfinder3/okadminfinder.py'

clear && echo "-- Installing XSStrike"
cd /opt/xsstrike/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/xsstrike && if [ \$(checksudo) = 0 ]; then (pipenv run python3 xsstrike.py \"\$@\");fi)" > /usr/bin/xsstrike'
sudo chmod +x /usr/bin/xsstrike
URL_GECKODRIVER=$(url_latest 'https://api.github.com/repos/mozilla/geckodriver/releases/latest' 'linux64')
curl -s -L "$URL_GECKODRIVER" | tar -xz
sudo chmod +x geckodriver
sudo mv geckodriver '/usr/local/bin'
check_app 'xsstrike' '/opt/xsstrike/xsstrike.py'

clear && echo "-- Installing WPScan"
sudo gem install wpscan
wpscan --update

clear && echo "-- Installing joomscan"
perl -i -pe 'y|\r||d' /opt/joomscan/joomscan.pl
sudo bash -c 'echo -e "#!/bin/bash\n(/opt/joomscan/joomscan.pl \"\$@\")" > /usr/bin/joomscan'
sudo chmod +x /usr/bin/joomscan
check_app 'joomscan' '/opt/joomscan/joomscan.pl'

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
git clone -q --depth 1 'https://github.com/almandin/fuxploider' '/opt/fuxploider'
cd /opt/fuxploider/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/fuxploider && if [ \$(checksudo) = 0 ]; then (pipenv run python3 fuxploider.py \"\$@\");fi)" > /usr/bin/fuxploider'
sudo chmod +x /usr/bin/fuxploider
check_app 'fuxploider' '/opt/fuxploider/fuxploider.py'

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing tplmap"
  git clone -q --depth 1 'https://github.com/epinna/tplmap' '/opt/tplmap'
  cd /opt/tplmap/
  pipenv --bare --two install -r requirements.txt
  sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/tplmap && if [ \$(checksudo) = 0 ]; then (pipenv run python2 tplmap.py \"\$@\");fi)" > /usr/bin/tplmap'
  sudo chmod +x /usr/bin/tplmap
fi

########## ---------- ##########
# Network
########## ---------- ##########

clear && echo "-- Installing proxychains" # https://github.com/rofl0r/proxychains-ng
sudo apt-get -qq install proxychains4

clear && echo "-- Installing sshuttle" # https://github.com/sshuttle/sshuttle
sudo apt-get -qq install sshuttle

clear && echo "-- Install nmap-parse-output" # https://github.com/ernw/nmap-parse-output
sudo apt-get -qq install xsltproc libxml2-utils
git clone -q --depth 1 'https://github.com/ernw/nmap-parse-output' '/opt/nmap-parse-output'
bash -c "echo -e 'source /opt/nmap-parse-output/_nmap-parse-output' >> /home/${USER}/.bashrc"
sudo ln -sf /opt/nmap-parse-output/nmap-parse-output /usr/local/bin/nmap-parse-output
check_app 'nmap-parse-output' '/opt/nmap-parse-output/nmap-parse-output'

clear && echo "-- Installing nmapAutomator"
git clone -q --depth 1 'https://github.com/wantafanta/nmapautomator' '/opt/nmapautomator'
cd /opt/nmapautomator/
sudo chmod +x nmapAutomator.sh
#sslscan, gobuster, nikto, joomscan, wpscan, droopescan, smbmap, smbclient, enum4linux, snmp-check, snmpwalk, dnsrecon, odat.py, 
check_app 'nmapautomator' '/opt/nmapautomator/nmapAutomator.sh'

clear && echo "-- Installing dnsrecon"
git clone -q --depth 1 'https://github.com/darkoperator/dnsrecon' '/opt/dnsrecon'
cd /opt/dnsrecon/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/dnsrecon && if [ \$(checksudo) = 0 ]; then (pipenv run python3 dnsrecon.py \"\$@\");fi)" > /usr/bin/dnsrecon'
sudo chmod +x /usr/bin/dnsrecon
check_app 'dnsrecon' '/opt/dnsrecon/dnsrecon.py'

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing Seth"
  git clone -q --depth 1 'https://github.com/SySS-Research/seth' '/opt/seth'
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
check_app 'wireshark' '/usr/bin/wireshark'

clear && echo "-- Installing termshark"
sudo apt-get -qq install tshark
URL_TERMSHARK=$(url_latest 'https://api.github.com/repos/gcla/termshark/releases/latest' 'linux_x64')
cd /opt/
wget -q $URL_TERMSHARK
tar xvf termshark*.tar.gz
sudo rm termshark*.tar.gz
mv termshark_*/ termshark/
sudo ln -sf /opt/termshark/termshark /usr/local/bin/termshark
check_app 'termshark' '/opt/termshark/termshark'

python3 -m pipx install credslayer # https://github.com/ShellCode33/credslayer

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
sudo sed -i 's/^set api.rest.username.*/set api.rest.username admin/g' /usr/local/share/bettercap/caplets/https-ui.cap
sudo sed -i 's/^set api.rest.password.*/set api.rest.password bettercap/g' /usr/local/share/bettercap/caplets/https-ui.cap
sudo bash -c 'echo -e "#!/bin/bash\n(sudo /opt/bettercap/bettercap \"\$@\")" > /usr/bin/bettercap'
sudo chmod +x /usr/bin/bettercap
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=bettercap\nExec=gnome-terminal --window -- bash -c '\''printf \"\\\n\\\n\" && nmcli d && printf \"\\\n\\\n\" && read -p \"Enter the device name: \" int && clear && sudo /opt/bettercap/bettercap -iface \$int -caplet http-ui'\''\nIcon=/opt/bettercap/logo.png\nCategories=Application;\nActions=app1;\n\n[Desktop Action app1]\nName=Web UI\nExec=firefox http://localhost:80" > /usr/share/applications/bettercap.desktop'
check_app 'bettercap' '/opt/bettercap/bettercap'

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
check_app 'beef' '/opt/beef/beef'

clear && echo "-- Installing wine"
sudo apt-get -qq install wine winbind winetricks xdotool
sudo dpkg --add-architecture i386 && sudo apt-get -qq update && sudo apt-get -qq install wine32
bash -c 'WINEARCH=win32 wine wineboot'

clear && echo "-- Installing FUZZBUNCH"
git clone -q --depth 1 'https://github.com/mdiazcl/fuzzbunch-debian' "$HOME/.wine/drive_c/fuzzbunch-debian"
bash -c "echo -e 'Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\\Environment]\n\"Path\"=\"c:\\\\\windows;c:\\\\\windows\\\\\system;C:\\\\\Python26;C:\\\\\\\fuzzbunch-debian\\\\\windows\\\\\\\fuzzbunch\"' > /home/${USER}/.wine/drive_c/system.reg"
bash -c "wine regedit.exe /s c:\\\system.reg"
bash -c "wine start /w c:\\\fuzzbunch-debian\\\installers\\\python-2.6.msi"
bash -c "wine start /w c:\\\fuzzbunch-debian\\\installers\\\pywin32-219.win32-py2.6.exe"
mkdir /opt/fuzzbunch
wget -q 'https://upload.wikimedia.org/wikipedia/commons/8/8d/Seal_of_the_U.S._National_Security_Agency.svg' -O '/opt/fuzzbunch/logo.svg'
sudo bash -c 'echo -e "#!/bin/bash\n(cd \$HOME/.wine/drive_c/fuzzbunch-debian/windows && wine cmd.exe /C python fb.py \"\$@\")" > /usr/bin/fuzzbunch'
sudo chmod +x /usr/bin/fuzzbunch
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=FUZZBUNCH\nExec=gnome-terminal --window -- fuzzbunch\nIcon=/opt/fuzzbunch/logo.svg\nCategories=Application;" > /usr/share/applications/fuzzbunch.desktop'
check_app 'fuzzbunch' "/home/${USER}/.wine/drive_c/fuzzbunch-debian/windows/fb.py"

clear && echo "-- Installing Mono"
sudo mkdir /usr/share/wine/mono
sudo wget -q $URL_MONO -O '/usr/share/wine/mono/wine-mono.msi'
bash -c "wine msiexec /i /usr/share/wine/mono/wine-mono.msi"

#clear && echo "-- Installing EvilClippy"
#sudo apt-get -qq install mono-mcs
#git clone -q --depth 1 'https://github.com/outflanknl/evilclippy' /opt/evilclippy
#cd /opt/evilclippy/
#mcs /reference:OpenMcdf.dll,System.IO.Compression.FileSystem.dll /out:EvilClippy.exe *.cs
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/evilclippy/ && wine EvilClippy.exe \"\$@\")" > /usr/bin/evilclippy'
#sudo chmod +x /usr/bin/evilclippy
#check_app 'evilclippy' '/opt/evilclippy/EvilClippy.exe'

if [[ $(py2_support) == "true" ]]; then
  clear && echo "-- Installing PRET"
  git clone -q --depth 1 'https://github.com/RUB-NDS/pret' '/opt/pret'
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
check_app 'ntlmrecon' '/opt/ntlmrecon/setup.py'

trap '' INT
clear && echo "-- Installing Nessus"
ID_NESSUS=$(curl -s 'https://www.tenable.com/downloads/nessus?loginAttempted=true' | grep -oE 'id=.?__NEXT_DATA__[^<>]*>[^<>]+' | cut -d'>' -f2 | jq -c '[ .props.pageProps.page.downloads[] | select( .description | contains("20.04")) ][] | select(.file | startswith("Nessus-10"))' | jq -r .id)
URL_NESSUS="https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/$ID_NESSUS/download?i_agree_to_tenable_license_agreement=true"
# nesus: https://www.tenable.com/downloads/nessus
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
trap - INT
wget -q -U firefox 'https://gist.githubusercontent.com/wantafanta/0d31a15974b41862b1fcbcb804c571be/raw/fd0b4cd4feff5f2eaed55a34db4e1f3be9e60fac/nessus-merge.py' -O '/opt/nessus-merge.py'
check_app 'nessus' '/opt/nessus/sbin/nessuscli'

clear && echo "-- Installing frogger2"
git clone -q --depth 1 'https://github.com/commonexploits/vlan-hopping' '/opt/vlan-hopping'
sudo apt-get -qq install yersinia vlan arp-scan screen
sudo chmod +x /opt/vlan-hopping/frogger2.sh
sudo ln -sf /opt/vlan-hopping/frogger2.sh /usr/local/bin/frogger
check_app 'frogger' '/opt/vlan-hopping/frogger2.sh'

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

clear && echo "-- Installing Maltego"
cd /opt/
wget -q $URL_MALTEGO
sudo apt-get -qq install ./Maltego*.deb
sudo rm Maltego*.deb

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
  git clone -q --depth 1 'https://github.com/vysec/linkedint' '/opt/linkedint'
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
python3 -m pipx install pymetadata

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
bash -c 'echo -e "keys add binaryedge_api <key>\nkeys add bing_api <key>\nkeys add builtwith_api <key>\nkeys add censysio_id <key>\nkeys add censysio_secret <key>\nkeys add flickr_api <key>\nkeys add fullcontact_api <key>\nkeys add github_api <key>\nkeys add google_api <key>\nkeys add hashes_api <key>\nkeys add hibp_api <key>\nkeys add ipinfodb_api <key>\nkeys add ipstack_api <key>\nkeys add namechk_api <key>\nkeys add pwnedlist_api <key>\nkeys add pwnedlist_iv <key>\nkeys add pwnedlist_secret <key>\nkeys add shodan_api <key>\nkeys add twitter_api <key>\nkeys add twitter_secret <key>\nkeys add virustotal_api <key>\nexit" > api.rc'
#recon-ng -r /opt/recon-ng/api.rc

#clear && echo "-- Installing Sudomy"
#git clone -q --depth 1 --recursive 'https://github.com/Screetsec/sudomy' '/opt/sudomy'
#sudo apt-get -qq install phantomjs npm
#sudo npm i -g wappalyzer --unsafe-perm=true
#cd /opt/sudomy/
#pipenv --bare --three install -r requirements.txt
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/sudomy && if [ \$(checksudo) = 0 ]; then (pipenv run bash sudomy \"\$@\");fi)" > /usr/bin/sudomy'
#sudo chmod +x /usr/bin/sudomy

#clear && echo "-- Installing httprobe (Sudomy)"
#cd /opt/
#mkdir httprobe
#cd /opt/httprobe/
#wget -q 'https://github.com/tomnomnom/httprobe/releases/download/v0.1.2/httprobe-linux-amd64-0.1.2.tgz'
#tar xvzf httprobe*.tgz
#sudo ln -sf /opt/httprobe/httprobe /usr/local/bin/httprobe

clear && echo "bopscrk (Before Outset PaSsword CRacKing)"
git clone -q --depth 1 'https://github.com/r3nt0n/bopscrk' '/opt/bopscrk'
cd /opt/bopscrk/
pipenv --bare --three install -r requirements.txt
sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/bopscrk && if [ \$(checksudo) = 0 ]; then (pipenv run python bopscrk.py \"\$@\");fi)" > /usr/bin/bopscrk'
sudo chmod +x /usr/bin/bopscrk

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

clear && echo "-- Installing Modlishka"
URL_MODLISHKA=$(url_latest 'https://api.github.com/repos/drk1wi/Modlishka/releases/latest' 'linux')
mkdir /opt/modlishka
cd /opt/modlishka/
wget -q $URL_MODLISHKA
sudo chmod +x /opt/modlishka/*
sudo ln -sf /opt/modlishka/Modlishka-linux-amd64 /usr/local/bin/modlishka

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
  sudo ln -sf /opt/creap/crEAP.py /usr/local/bin/creap
fi

#clear && echo "-- Installing eaphammer"
#cd /opt/eaphammer/
#sudo ./kali-setup
#pipenv --bare --three run sudo pip3 install -r pip.req
#sudo bash -c 'echo -e "#!/bin/bash\n(cd /opt/eaphammer/ && if [ \$(checksudo) = 0 ]; then (pipenv run sudo python3 eaphammer \"\$@\");fi)" > /usr/bin/eaphammer'
#sudo chmod +x /usr/bin/eaphammer

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

if [[ $(py2_support) == "true" ]]; then # libqt4-dev not in 20.04 repo
  clear && echo "-- Installing proxmark3"
  git clone -q --depth 1 'https://github.com/Proxmark/proxmark3' '/opt/proxmark3'
  cd /opt/proxmark3/
  sudo apt-get -qq install p7zip-full build-essential libreadline5 libreadline-dev libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi libstdc++-arm-none-eabi-newlib libpcsclite-dev pcscd
  sudo cp -rf driver/77-mm-usb-device-blacklist.rules /etc/udev/rules.d/77-mm-usb-device-blacklist.rules
  sudo udevadm control --reload-rules
  sudo adduser ${USER} dialout
  sudo make clean && sudo make all
  sudo ln -sf /opt/proxmark3/client/proxmark3 /usr/local/bin/proxmark3
fi

clear && echo "-- Installing Go"
if [[ $(py2_support) == "true" ]]; then # not in < 20.04 repo
  sudo add-apt-repository -y ppa:longsleep/golang-backports
  sudo apt-get -qq update
fi
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

clear && echo "-- Installing draw.io"
URL_DRAWIO=$(url_latest 'https://api.github.com/repos/jgraph/drawio-desktop/releases/latest' 'drawio-amd64-')
cd /opt/
wget -q $URL_DRAWIO
sudo apt-get -qq install ./drawio*.deb
sudo rm drawio*.deb
git clone -q --depth 1 'https://github.com/michenriksen/drawio-threatmodeling' '/opt/drawio-threatmodeling'

clear && echo "-- Installing Obsidian"
cd /opt/
URL_OBSIDIAN=$(url_latest 'https://api.github.com/repos/obsidianmd/obsidian-releases/releases/latest' '.AppImage')
mkdir /opt/obsidian
wget -q $URL_OBSIDIAN -O '/opt/obsidian/obsidian.AppImage'
sudo chmod +x /opt/obsidian/obsidian.AppImage
sudo ln -sf /opt/obsidian/obsidian.AppImage /usr/local/bin/obsidian
wget -q 'https://raw.githubusercontent.com/kmaasrud/awesome-obsidian/master/media/obsidian_logo.png' -O '/opt/obsidian/icon.png'
sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=Obsidian\nExec=obsidian\nIcon=/opt/obsidian/icon.png\nCategories=Application;" > /usr/share/applications/obsidian.desktop'
mkdir "/home/${USER}/.local/share/appimagekit/" && touch "/home/${USER}/.local/share/appimagekit/no_desktopintegration"

clear && echo '-- Installing some "Gitbooks"'
mkdir /opt/gitbook/
git clone -q --depth 1 'https://github.com/carlospolop/hacktricks' '/opt/gitbook/hacktricks'
git clone -q --depth 1 'https://github.com/swisskyrepo/PayloadsAllTheThings' '/opt/gitbook/payloadsallthethings'
git clone -q --depth 1 'https://github.com/The-Viper-One/Pentest-everything' '/opt/gitbook/pentest-everything'

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
#sudo bash -c 'echo -e "#!/usr/bin/env xdg-open\n[Desktop Entry]\nType=Application\nName=cve-search\nExec=firefox http://localhost:5000\nIcon=/opt/cve-search/web/static/img/favicon.ico\nCategories=Application;" > /usr/share/applications/cve-search.desktop'

########## ---------- ##########
# End
########## ---------- ##########

# Reset the Dock favourites
sudo -u ${USER} DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${RUSER_UID}/bus" dconf write /org/gnome/shell/favorite-apps "['firefox.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Terminal.desktop',  'google-chrome.desktop', 'nessus.desktop', 'BurpSuiteCommunity.desktop', 'BurpSuitePro.desktop', 'cyberchef.desktop', 'metasploit-framework.desktop', 'covenant.desktop', 'empire.desktop', 'bloodhound.desktop', 'bettercap.desktop', 'wireshark.desktop','pwndoc.desktop','obsidian.desktop']"

# Services fixes
# sudo systemctl stop apache2.service #eaphammer
# sudo systemctl disable apache2.service #eaphammer
sudo systemctl stop lighttpd.service #fluxion
sudo systemctl disable lighttpd.service #fluxion

# Cleanup apt
sudo apt-get autoremove -y
# fix empire
sudo pip3 install -r /opt/empire/setup/requirements.txt
sudo pip3 install pyparsing
#cd /opt/empire/
#sudo ./setup/reset.sh

# Fix VMware display
sudo sed -i 's/Before=cloud-init-local.service/Before=cloud-init-local.service\nAfter=display-manager.service/g' /lib/systemd/system/open-vm-tools.service

# Clear terminal history
sudo cat /dev/null > "/home/${USER}/.bash_history" && history -c
sudo chown -R ${USER}:${USER} "/home/${USER}/.bash_history"

# Set permissions in /opt/
sudo chown -R ${USER}:${USER} /opt/
sudo chmod -R 777 /opt/natlas/

# Set neo4j database password to "bloodhound"
sudo neo4j-admin set-initial-password bloodhound
#echo "ALTER USER neo4j SET PASSWORD 'bloodhound'" | cypher-shell -d system
#sudo systemctl stop neo4j.service
#sudo sed -i 's/dbms.security.auth_enabled=false/#dbms.security.auth_enabled=false/g' /etc/neo4j/neo4j.conf
#sudo systemctl start neo4j.service

# Update the mlocate database
sudo updatedb

clear && echo -e "Done.\nAll modules stored in /opt/"
#echo 'View Docker images via "sudo docker images"'
#echo 'Run "msfconsole" to setup initial msf database'
#echo 'Run "cme" to setup initial CrackMapExec database'
echo -e "\n-- Notes:"
echo 'To resolve .onion addresses (via torghost) open about:config in Firefox and set network.dns.blockDotOnion to false'
echo -e "\n-- Creds:"
echo 'BeEF username and password have been set ( u:admin p:beef )'
echo 'bettercap UI username and password have been set ( u:admin p:bettercap )'
echo 'BloodHound Database username and password have been set ( u:neo4j p:bloodhound )'
echo 'Empire username and password are default ( u:empireadmin p:password123 )'
echo 'pwndrop username and password have been set ( u:admin p:pwndrop )'
echo -e "\nPress Enter to reboot."
read -p "" </dev/tty

# Clear terminal history
sudo cat /dev/null > "/home/${USER}/.bash_history" && history -c
sudo chown -R ${USER}:${USER} "/home/${USER}/.bash_history"

# Reboot
sudo reboot now