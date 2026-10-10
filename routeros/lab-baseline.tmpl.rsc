# The segment address and DHCP server every scenario starts from (lab #9).
# The seed imports it once; the routeros adapter's Recover imports it again.
/ip dhcp-server network remove [find]
/ip dhcp-server matcher remove [find]
/ip dhcp-server option sets remove [find]
/ip dhcp-server option remove [find]
/ip pool remove [find name~"^labf"]
/ip address remove [find interface=ether2]
/ip address add interface=ether2 address=__SEG_ADDR__
:if ([:len [/ip pool find name=lab]] = 0) do={/ip pool add name=lab ranges=__POOL_START__-__POOL_END__} else={/ip pool set [find name=lab] ranges=__POOL_START__-__POOL_END__}
:if ([:len [/ip pool find name=b5]] = 0) do={/ip pool add name=b5 ranges=__CLASS_POOL_START__-__CLASS_POOL_END__} else={/ip pool set [find name=b5] ranges=__CLASS_POOL_START__-__CLASS_POOL_END__}
:if ([:len [/ip dhcp-server find name=lab]] = 0) do={/ip dhcp-server add name=lab interface=ether2 address-pool=lab lease-time=30m} else={/ip dhcp-server set [find name=lab] interface=ether2 address-pool=lab lease-time=30m disabled=no}
/ip dhcp-server network add address=__SEG_SUBNET__ gateway=__SEG_GATEWAY__
/ip dhcp-server matcher add server=lab name=b5 code=60 value="lab-class-b5" address-pool=b5 matching-type=exact
