# SoftEther's own vpnclient, for the server-direction cell.
#
# Derived from the same siomiz/softethervpn image the other two SoftEther cells
# already pin rather than being a second peer: that image ships vpnserver,
# vpnclient and vpncmd from one build, so the reverse direction needed no new
# implementation -- only iperf3, which the base image does not carry and which
# the throughput table needs from whichever container holds the tunnel address.
#
# Adding iperf3 rather than accepting a dash is deliberate. The README defines
# the dash as "iperf3 does not apply to that cell", and here it applies: the
# veepin server's TAP and this client's virtual NIC both hold an address inside
# the segment. The client-direction cell keeps its dash for the reason stated
# there -- SecureNAT's gateway is not an address anything can bind.
FROM siomiz/softethervpn:latest
RUN apk add --no-cache iperf3
