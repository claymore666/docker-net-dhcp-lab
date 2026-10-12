# Run through the guest agent's guest-exec before anything else (lab #9).
# It keeps the vendor config as lab-stock.rsc, the stock side of the config
# diff, once; closes every service but ssh and IPv6 while admin still has
# the blank password; then sets the mgmt address and route the seed's ssh
# login needs. guest-exec may write config but not users (M3).
:if ([:len [/file find name=lab-stock.rsc]] = 0) do={/export file=lab-stock}
/ip service disable [find name!=ssh dynamic=no]
/ipv6 settings set disable-ipv6=yes
/ip dhcp-client remove [find]
:if ([:len [/ip address find interface=ether1 address="__MGMT_ADDR__"]] = 0) do={/ip address add interface=ether1 address=__MGMT_ADDR__}
:if ([:len [/ip route find dst-address=0.0.0.0/0 gateway=__MGMT_GW__]] = 0) do={/ip route add dst-address=0.0.0.0/0 gateway=__MGMT_GW__}
