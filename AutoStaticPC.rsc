# jan/26/2025 18:12:12 by RouterOS 6.49.10
# software id = 00YY-E4BP
#
# model = RB750Gr3
# serial number = HCP08EADWXB
/system script
add dont-require-permissions=no name=AutoStaticPC owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="#\
    \_-----------------------------------------------------------\r\
    \n# 1) \CF\EE\EB\F3\F7\E0\E5\EC DHCP Server, \F1\E5\F2\FC \E8 baseNetwork\
    \r\
    \n# -----------------------------------------------------------\r\
    \n:local dhcpServer [/ip dhcp-server find];\r\
    \n:if ([:len \$dhcpServer] = 0) do={\r\
    \n    :put \"No DHCP server found!\";\r\
    \n    :error \"DHCP server not configured.\";\r\
    \n}\r\
    \n\r\
    \n:local dhcpServerName [/ip dhcp-server get \$dhcpServer name];\r\
    \n:put (\"DHCP Server: \" . \$dhcpServerName);\r\
    \n\r\
    \n:local networkConfig [/ip dhcp-server network find];\r\
    \n:if ([:len \$networkConfig] = 0) do={\r\
    \n    :put \"No DHCP network found!\";\r\
    \n    :error \"DHCP network not configured.\";\r\
    \n}\r\
    \n\r\
    \n:local networkAddress [/ip dhcp-server network get \$networkConfig addre\
    ss];\r\
    \n:if ([:len \$networkAddress] = 0) do={\r\
    \n    :put \"No network address configured!\";\r\
    \n    :error \"Network address not found.\";\r\
    \n}\r\
    \n:put (\"Network Address: \" . \$networkAddress);\r\
    \n\r\
    \n# \D3\E1\E8\F0\E0\E5\EC \EC\E0\F1\EA\F3 /24 \E8 \F2.\EF. \E5\F1\EB\E8 \
    \E5\F1\F2\FC\r\
    \n:local slashIndex [:find \$networkAddress \"/\"];\r\
    \n:if (\$slashIndex != -1) do={\r\
    \n    :set networkAddress [:pick \$networkAddress 0 \$slashIndex];\r\
    \n}\r\
    \n:put (\"Subnet: \" . \$networkAddress);\r\
    \n\r\
    \n# \D4\F3\ED\EA\F6\E8\FF \"\EE\F2\EA\F3\F1\E8\F2\FC\" \EF\EE\F1\EB\E5\E4\
    \ED\E8\E9 \EE\EA\F2\E5\F2 (192.168.83.0 -> 192.168.83)\r\
    \n:global getBaseNetwork do={\r\
    \n    :local fullAddr \$1\r\
    \n\r\
    \n    :local firstDotIndex  [:find \$fullAddr \".\"];\r\
    \n    :local secondDotIndex [:find \$fullAddr \".\" (\$firstDotIndex + 1)]\
    ;\r\
    \n    :local thirdDotIndex  [:find \$fullAddr \".\" (\$secondDotIndex + 1)\
    ];\r\
    \n\r\
    \n    :local oct1 [:pick \$fullAddr 0 \$firstDotIndex];\r\
    \n    :local oct2 [:pick \$fullAddr (\$firstDotIndex + 1) \$secondDotIndex\
    ];\r\
    \n\r\
    \n    :local oct3 \"\"\r\
    \n    :if (\$thirdDotIndex != -1) do={\r\
    \n        :set oct3 [:pick \$fullAddr (\$secondDotIndex + 1) \$thirdDotInd\
    ex];\r\
    \n    } else={\r\
    \n        :set oct3 [:pick \$fullAddr (\$secondDotIndex + 1) [:len \$fullA\
    ddr]];\r\
    \n    }\r\
    \n\r\
    \n    :return (\$oct1 . \".\" . \$oct2 . \".\" . \$oct3);\r\
    \n};\r\
    \n\r\
    \n:local baseNetwork [\$getBaseNetwork \$networkAddress];\r\
    \n:put (\"Base Network (3 octets): \" . \$baseNetwork);\r\
    \n\r\
    \n# -----------------------------------------------------------\r\
    \n# 2) \D6\E8\EA\EB \EF\EE \E4\E8\ED\E0\EC\E8\F7\E5\F1\EA\E8\EC \E0\F0\E5\
    \ED\E4\E0\EC: \F3\E4\E0\EB\FF\E5\EC, \F1\EE\E7\E4\E0\B8\EC \F1\F2\E0\F2\E8\
    \F7\E5\F1\EA\E8\E9\r\
    \n# -----------------------------------------------------------\r\
    \n:foreach lease in=[/ip dhcp-server lease find dynamic=yes] do={\r\
    \n\r\
    \n    :local macAddr  [/ip dhcp-server lease get \$lease mac-address];\r\
    \n    :local hostName [/ip dhcp-server lease get \$lease host-name];\r\
    \n\r\
    \n    # \CF\F0\EE\E2\E5\F0\FF\E5\EC, \E5\F1\F2\FC \EB\E8 \F5\EE\F2\FF \E1\
    \FB 2 \EF\EE\F1\EB\E5\E4\ED\E8\F5 \F1\E8\EC\E2\EE\EB\E0\r\
    \n    :if ([:len \$hostName] >= 2) do={\r\
    \n\r\
    \n        :local lastTwoChars [:pick \$hostName ([:len \$hostName] - 2) [:\
    len \$hostName]];\r\
    \n\r\
    \n        # \CF\F0\EE\E2\E5\F0\FF\E5\EC, \E4\E5\E9\F1\F2\E2\E8\F2\E5\EB\FC\
    \ED\EE \EB\E8 \FD\F2\EE \F6\E8\F4\F0\FB\r\
    \n        :if ([:typeof [:tonum \$lastTwoChars]] = \"num\") do={\r\
    \n\r\
    \n            # \D1\F7\E8\F2\E0\E5\EC \ED\EE\E2\FB\E9 \EF\EE\F1\EB\E5\E4\
    \ED\E8\E9 \EE\EA\F2\E5\F2 \EA\E0\EA 100 + \FD\F2\E8 2 \F6\E8\F4\F0\FB\r\
    \n            :local lastOctet (100 + [:tonum \$lastTwoChars]);\r\
    \n\r\
    \n            # \D4\EE\F0\EC\E8\F0\F3\E5\EC IP-\E0\E4\F0\E5\F1: \"192.168.\
    83.130\"\r\
    \n            :local newIP (\$baseNetwork . \".\" . \$lastOctet);\r\
    \n\r\
    \n            :put (\"---\");\r\
    \n            :put (\"Removing dynamic lease: hostName=\" . \$hostName . \
    \", MAC=\" . \$macAddr);\r\
    \n            /ip dhcp-server lease remove \$lease;\r\
    \n\r\
    \n            # \C5\F1\EB\E8 \F3\E6\E5 \F1\F3\F9\E5\F1\F2\E2\F3\E5\F2 leas\
    e \F1 \F2\E0\EA\E8\EC IP, \F2\EE\E6\E5 \F3\E4\E0\EB\E8\EC (\F4\EE\F0\F1\E8\
    \F0\EE\E2\E0\ED\ED\E0\FF \EB\EE\E3\E8\EA\E0)\r\
    \n            :local conflictLease [/ip dhcp-server lease find where addre\
    ss=\$newIP];\r\
    \n            :if ([:len \$conflictLease] > 0) do={\r\
    \n                :put (\"Removing old lease with same IP: \" . \$newIP);\
    \r\
    \n                /ip dhcp-server lease remove \$conflictLease;\r\
    \n            }\r\
    \n\r\
    \n            # \D1\EE\E7\E4\E0\B8\EC \ED\EE\E2\FB\E9 \F1\F2\E0\F2\E8\F7\
    \E5\F1\EA\E8\E9 lease\r\
    \n            /ip dhcp-server lease add \\\r\
    \n                address=\$newIP \\\r\
    \n                mac-address=\$macAddr \\\r\
    \n                server=(\$dhcpServerName);\r\
    \n\r\
    \n            :put (\"New static lease added: \" . \$newIP . \" / \" . \$m\
    acAddr);\r\
    \n        }\r\
    \n    }\r\
    \n}"
