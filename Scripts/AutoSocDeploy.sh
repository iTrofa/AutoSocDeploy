#!/bin/bash

cat << EOF > .bashrc

PS1='\[\033[01;36m\]\t \[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]$ '
umask 022

HISTCONTROL=ignoredups:ignorespace
HISTFILESIZE=200000
HISTSIZE=100000

export PROMPT_COMMAND="history -a; history -n"

export LS_OPTIONS='--color=auto'
eval "LS_COLORS='rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:';
export LS_COLORS"
alias ls='ls $LS_OPTIONS'
alias ll='ls  -l'
alias l='ls  -lA'
alias llh='ll -h'
# Some more alias to avoid making mistakes:
alias rm='rm -iv --preserve-root'
alias cp='cp -iv'
alias mv='mv -iv'
alias chmod='chmod -v --preserve-root'
alias chown='chown -v --preserve-root'
alias mount='mount -v'
alias umount='umount -flv'
alias su='su -'
alias c='clear'
alias cls='clear'
#figlet -c -f standard TROFA
#echo ########################################################################
alias plantu="netstat -plantu"
alias rgrep="find . -type f|xargs grep -win --color"
alias df="df -Th| grep -Ev '(udev|tmpfs)'"

EOF
source .bashrc

# Update package lists
apt-get update

# Install necessary packages
apt-get install -y software-properties-common
apt-add-repository --yes --update ppa:ansible/ansible
apt-get install -y ansible

# Configure Ansible
mkdir /etc/ansible
touch /etc/ansible/hosts

# Add localhost to inventory file
echo "[localhost]" >> /etc/ansible/hosts
echo "127.0.0.1" >> /etc/ansible/hosts


ssh-keygen -t rsa -b 4096 -C "ansible" -f /root/.ssh/id_rsa -N ''
cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
systemctl restart ssh

# Ansible dependencies

apt install -y sudo
apt install -y curl
apt install -y unzip

mkdir /root/ansible_playbooks
unzip Scripts.zip -d ansible_playbooks
cd /root/ansible_playbooks/

#Install Splunk

ansible-playbook splunk_install.yaml

# we put Splunk in english
chmod +w /opt/splunk/lib/python3.7/site-packages/splunk/appserver/mrsparkle/lib/util.py
sed -i '1679s/locale = "%s-%s" % (locale\[0\], locale1) if locale1 else locale\[0\]/locale = "en-US"/' /opt/splunk/lib/python3.7/site-packages/splunk/appserver/mrsparkle/lib/util.py
/opt/splunk/bin/splunk restart

# Here we will ask for ip of remote host

# make ansible connect over ssh key

# So we can use password with SSH to send our SSH key
apt install sshpass -y

read -p "Do you want to add a Linux server? (Yes/No): " add_Linux_server

if [[ "$add_Linux_server" =~ ^[Yy]([Ee][Ss])?$ ]]; then
  # Prompt the user to enter the Linux IP address
  read -p "Enter the Linux IP address: " Linux_ip

  # Prompt the user to enter the SSH port
  read -p "Enter the SSH port (default is 22): " SSH_port
  SSH_port=${SSH_port:-22}

  # Prompt the user to enter the username
  read -p "Enter the Linux username: " Linux_username

  # Prompt the user to enter the password (the -s flag hides the input)
  read -s -p "Enter the Linux password: " Linux_password

  # Check if the IP address is already in the Ansible inventory file
  if grep -q $Linux_ip /etc/ansible/hosts; then
    echo "IP address already exists in the Ansible inventory file."
  else
    # Append the IP address to the Ansible inventory file
    echo -e "\n[$Linux_ip]\n$Linux_ip:$SSH_port ansible_user=$Linux_username ansible_ssh_private_key_file=~/.ssh/id_rsa" >> /etc/ansible/hosts
  fi

  # Copy SSH key to the Linux server using sshpass for password automation
  sshpass -p $Linux_password ssh-copy-id -o StrictHostKeyChecking=no -p $SSH_port $Linux_username@$Linux_ip

  # Run the Ansible playbook with the provided variables
  ansible-playbook linux_forwarder.yaml -e "Linux_ip=$Linux_ip"

  # make sure /opt/splunkforwarder is not already installed in remote machine because apt doesn't reinstall it.

  echo -e "\n[Splunk_Server]" >> /etc/ansible/hosts && echo "$(hostname -I | awk '{print $1}')" >> /etc/ansible/hosts

  ansible-playbook linux_splunk_config.yaml -e "Linux_ip=$Linux_ip"  --extra-vars "Splunk_Server=$(hostname -I | awk '{print $1}')"

  # We install auditd

  ansible-playbook auditd.yaml  -e "Linux_ip=$Linux_ip"

  # We install Tango App to help analyze our Linux Honeypot

  mv /root/ansible_playbooks/tango-honeypot-intelligence_21.tgz /tmp/tango-honeypot-intelligence_21.tgz

elif [[ "$add_Linux_server" =~ ^[Nn]([Oo])?$ ]]; then
  echo "No Linux server will be added."

else
  echo "Please enter either Yes or No."
  read -p "Do you want to add a Linux server? (Yes/No): " add_Linux_server

  if [[ "$add_Linux_server" =~ ^[Yy]([Ee][Ss])?$ ]]; then
    # Prompt the user to enter the Linux IP address
    read -p "Enter the Linux IP address: " Linux_ip

    # Prompt the user to enter the SSH port
    read -p "Enter the SSH port (default is 22): " SSH_port
    SSH_port=${SSH_port:-22}

    # Prompt the user to enter the username
    read -p "Enter the Linux username: " Linux_username

    # Prompt the user to enter the password (the -s flag hides the input)
    read -s -p "Enter the Linux password: " Linux_password

    # Check if the IP address is already in the Ansible inventory file
    if grep -q $Linux_ip /etc/ansible/hosts; then
      echo "IP address already exists in the Ansible inventory file."
    else
      # Append the IP address to the Ansible inventory file
      echo -e "\n[$Linux_ip]\n$Linux_ip:$SSH_port ansible_user=$Linux_username ansible_ssh_private_key_file=~/.ssh/id_rsa" >> /etc/ansible/hosts
    fi

    # Copy SSH key to the Linux server using sshpass for password automation
    sshpass -p $Linux_password ssh-copy-id -o StrictHostKeyChecking=no -p $SSH_port $Linux_username@$Linux_ip

	# Run the Ansible playbook with the provided variables
    ansible-playbook linux_forwarder.yaml -e "Linux_ip=$Linux_ip"
    # make sure /opt/splunkforwarder is not already installed in remote machine because apt doesn't reinstall it.

    echo -e "\n[Splunk_Server]" >> /etc/ansible/hosts && echo "$(hostname -I | awk '{print $1}')" >> /etc/ansible/hosts

    ansible-playbook linux_splunk_config.yaml -e "Linux_ip=$Linux_ip"  --extra-vars "Splunk_Server=$(hostname -I | awk '{print $1}')"

    # We install auditd

    ansible-playbook auditd.yaml  -e "Linux_ip=$Linux_ip"

    # We install Tango App to help analyze our Linux Honeypot

    mv /root/ansible_playbooks/tango-honeypot-intelligence_21.tgz /tmp/tango-honeypot-intelligence_21.tgz

  elif [[ "$add_Linux_server" =~ ^[Nn]([Oo])?$ ]]; then
    echo "No Linux server will be added."

  else
    echo "Invalid input. No Linux server will be added."
  fi
fi


ansible-playbook apply_alerts.yaml

unset $add_Linux_server
unset $SSH_port
unset $Linux_ip
unset $Linux_password
unset $Linux_username

# Windows

# sshpass windows_cred #command send forwarder .zip / unzip it
# send registry key
# either start service or restart it
# add kfsenslog to monitor
# restart forwarder by sshpass
# sysmon ?

if [[ "$add_Windows_server" =~ ^[Yy]([Ee][Ss])?$ ]]; then
  # Prompt the user to enter the Windows IP address
  read -p "Enter the Windows IP address: " Windows_ip

  # Prompt the user to enter the SSH port
  read -p "Enter the SSH port (default is 22): " SSH_port
  SSH_port=${SSH_port:-22}

  # Prompt the user to enter the username
  read -p "Enter the Windows username: " Windows_username

  # Prompt the user to enter the password (the -s flag hides the input)
  read -s -p "Enter the Windows password: " Windows_password

  # Check if the IP address is already in the Ansible inventory file
  if grep -q $Windows_ip /etc/ansible/hosts; then
    echo "IP address already exists in the Ansible inventory file."
  else
    # Append the IP address to the Ansible inventory file
    echo -e "\n[$Windows_ip]\n$Windows_ip:$SSH_port ansible_user=$Windows_username ansible_ssh_private_key_file=~/.ssh/id_rsa" >> /etc/ansible/hosts
  fi

  # Copy SSH key to the Linux server using sshpass for password automation
  sshpass -p $Windows_password ssh-copy-id -o StrictHostKeyChecking=no -p $SSH_port $Windows_username@$Windows_ip

  # We install sysmon?

elif [[ "$add_Windows_server" =~ ^[Nn]([Oo])?$ ]]; then
  echo "No Linux server will be added."

else
  echo "Please enter either Yes or No."
  read -p "Do you want to add a Windows server? (Yes/No): " add_Windows_server

  if [[ "$add_Windows_server" =~ ^[Yy]([Ee][Ss])?$ ]]; then
    # Prompt the user to enter the Linux IP address
    read -p "Enter the Windows IP address: " Windows_ip

    # Prompt the user to enter the SSH port
    read -p "Enter the SSH port (default is 22): " SSH_port
    SSH_port=${SSH_port:-22}

    # Prompt the user to enter the username
    read -p "Enter the Windows username: " Windows_username

    # Prompt the user to enter the password (the -s flag hides the input)
    read -s -p "Enter the Windows password: " Windows_password

    # Check if the IP address is already in the Ansible inventory file
    if grep -q $Windows_ip /etc/ansible/hosts; then
      echo "IP address already exists in the Ansible inventory file."
    else
      # Append the IP address to the Ansible inventory file
      echo -e "\n[$Windows_ip]\n$Windows_ip:$SSH_port ansible_user=$Windows_username ansible_ssh_private_key_file=~/.ssh/id_rsa" >> /etc/ansible/hosts
    fi

    # Copy SSH key to the Linux server using sshpass for password automation
    sshpass -p $Windows_password ssh-copy-id -o StrictHostKeyChecking=no -p $SSH_port $Windows_username@$Windows_ip

    # We install sysmon ?

  elif [[ "$add_Windows_server" =~ ^[Nn]([Oo])?$ ]]; then
    echo "No Windows server will be added."

  else
    echo "Invalid input. No Windows server will be added."
  fi
fi


cd /root

# SSH into the Windows machine and execute the registry file
# Check Windows OpenSSH server is set to auto start after reboot
sshpass -p Admin123 scp -o StrictHostKeyChecking=no forwarder_service.reg "trofa@192.168.1.47:C:\\Users\\trofa\\Desktop\\forwarder_service.reg"

## Before sending zip file we might have to unzip it locally on linux edit the inputs file config it in Linux rezip it and then send zip file to Windows ##
sshpass -p Admin123 scp -o StrictHostKeyChecking=no SplunkUniversalForwarder.zip "trofa@192.168.1.47:C:\\Users\\trofa\\Desktop\\SplunkUniversalForwarder.zip"

sshpass -p Admin123 ssh -o StrictHostKeyChecking=no trofa@192.168.1.47 "regedit /s C:\\Users\\trofa\\Desktop\\forwarder_service.reg"

# Install 7z on remote Windows machine beforehand
sshpass -p Admin123 ssh -o StrictHostKeyChecking=no trofa@192.168.1.47 "\"C:\\Program Files\\7-Zip\\7z.exe\" x \"C:\\Users\\trofa\\Desktop\\splunkuniversalforwarder.zip\" -o\"C:\\\""

# Reboot the Windows machine
sshpass -p Admin123 ssh trofa@192.168.1.47 "shutdown /r /t 0"

# Wait for the Windows machine to become accessible again
echo "Waiting for Windows machine to restart..."
sleep 30  # Adjust the sleep duration as needed

# SSH into the Windows machine and start Splunk
# make sure honeypot is not taking port 8089
sshpass -p Admin123 ssh trofa@192.168.1.47 "C:\\splunkuniversalforwarder\\bin\\splunk start"

unset $add_Windows_server
unset $SSH_port
unset $Windows_ip
unset $Windows_password
unset $Windows_username
