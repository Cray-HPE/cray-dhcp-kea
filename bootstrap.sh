#!/bin/bash

zypper -n install docker git vim
systemctl start docker
systemctl enable docker
usermod -G docker -a vagrant
pip install docker-compose
chmod +x /home/vagrant/cray-dhcp-kea/*.sh