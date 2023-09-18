#!/bin/bash
# Copyright 2023 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# wait for kea server to start
i=1
while [[ $i -le 600 && ! -S /cray-dhcp-kea-socket/cray-dhcp-kea.socket ]]
do
    i=$(( $i + 1 ))
    sleep 10
done
( echo "cat <<EOF" ; cat /srv/kea/cray-dhcp-kea-ctrl-agent.conf  ; echo EOF ) | sh > /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
sed -i 's/EOF//g' /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
#  helpful for debugging
cat /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
# what we use to run Cray Dhcp Kea control agent(api)
/usr/local/sbin/kea-ctrl-agent -c /usr/local/kea/cray-dhcp-kea-ctrl-agent.conf
