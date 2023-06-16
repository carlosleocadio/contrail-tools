## Get contrail controller introspect traces
#!/bin/bash
## CFTS - Carlos Leocadio

HN=$(hostname -s)
KEYFILE='/etc/contrail/ssl/private/server-privkey.pem'
CERT='/etc/contrail/ssl/certs/server.pem'

#Set RI (x:y:a:b) and PREFIX (1.2.3.4) variables in order to query specific Routing Instance
RI=
PREFIX=
DATE=$(date +"%Y%m%dT%H%M%S")

# UVEs
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshUVECacheReq?x=XmppPeerInfoData | xmllint --format - >  "${HN}_XmppPeerInfoData.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshUVECacheReq?x=NodeStatus | xmllint --format - >  "${HN}_NodeStatus.xml"

# XMPP peers
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ShowXmppConnectionReq | xmllint --format - >  "${HN}_Snh_ShowXmppConnectionReq.xml"

# Snh_SandeshTraceRequest
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=ConfigClientRabbitMsgTraceBuf | xmllint --format - > "${HN}_ConfigClientRabbitMsgTraceBuf.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=ConfigClientTraceBuf | xmllint --format - > "${HN}_ConfigClientTraceBuf.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=IFMapTraceBuf | xmllint --format - > "${HN}_IFMapTraceBuf.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=IFMapUpdateSenderBuf | xmllint --format - > "${HN}_IFMapUpdateSenderBuf.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=IFMapXmppTraceBuf | xmllint --format - > "${HN}_IFMapXmppTraceBuf.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=BgpPeerObjectTraceBuf | xmllint --format - > "${HN}_BGPPeerObjectTraceBuf.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=BgpTraceBuf | xmllint --format - > "${HN}_BGPTraceBuf.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=RoutingInstanceTraceBuf | xmllint --format - > "${HN}_RoutingInstanceTraceBuf.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=IFMapRoutingInstanceTraceBuf | xmllint --format - > "${HN}_IFMapRoutingInstaceTraceBuf.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=XmppMessageTrace | xmllint --format - > "${HN}_XmppMessageTrace.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_SandeshTraceRequest?x=XmppTrace | xmllint --format - > "${HN}_XmppTrace.xml"

curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ShowBgpNeighborSummaryReq | xmllint --format - > "${HN}_BgpNeighborSummaryReq.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ShowRouteSummaryReq | xmllint --format - > "${HN}_RouteSummaryReq.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ShowRoutingInstanceReq | xmllint --format - > "${HN}_routing_instance_request.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ShowRoutingInstanceSummaryReq | xmllint --format - > "${HN}_routing_instance_summary_request.xml"

# RouteReq
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ShowRouteReq?routing_table=&routing_instance=$RI&prefix=$PREFIX&longer_match=&shorter_match=&count=&start_routing_table=&start_routing_instance=&start_prefix=&source=&protocol=&family=inet | xmllint --format - >  "${HN}_ShowRouteReq_${RI}_${PREFIX}.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ShowRouteReq?routing_table=&prefix=&longer_match=&shorter_match=&count=&start_routing_table=&start_routing_instance=&start_prefix=&source=&protocol=&family=inet | xmllint --format - >  "${HN}_ShowRouteReq_All.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ShowRouteReq?x=inet.0 | xmllint --format - > "${HN}_RouteReq_inet0.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ShowRouteReq?x=bgp.evpn.0 | xmllint --format - > "${HN}_RouteReq_bgpEvp0.xml"

curl -s -k --key $KEYFILE --cert $CERT http://127.0.0.1:8083/Snh_ShowStaticRouteReq?search_string=RI  | xmllint --format - > "${HN}_static_route_request.xml"


# IFMapTable
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_IFMapTableShowReq?x=bgp-peering | xmllint --format - > "${HN}_bgp-peering.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_IFMapTableShowReq?x=bgp-router | xmllint --format - > "${HN}_bgp-router.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_IFMapTableShowReq?x=routing-instance | xmllint --format - > "${HN}_routing-instance.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_IFMapTableShowReq?x=virtual_network | xmllint --format - > "${HN}_IFMAPTableShowReq_virtual_network.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_IFMapTableShowReq?x=virtual_machine | xmllint --format - > "${HN}_IFMAPTableShowReq_virtual_machine.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_IFMapTableShowReq?x=virtual_machine-interface | xmllint --format - > "${HN}_IFMAPTableShowReq_virtual_machine.xml"
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_IFMapTableShowReq?x=virtual_router | xmllint --format - > "${HN}_IFMAPTableShowReq_virtual_router.xml"


# Snh_ConfigDBUUIDCacheReq
curl -s -k --key $KEYFILE --cert $CERT https://127.0.0.1:8083/Snh_ConfigDBUUIDCacheReq?search_string=$RI | xmllint --format - > "${HN}_uuid_cache_routing_instance.xml"
curl -s -k --key $KEYFILE --cert $CERT http://127.0.0.1:8083/Snh_ConfigDBUUIDCacheReq?search_string=virtual_machine | xmllint --format - > "${HN}_uuid_cache_virtual_machine.xml"
curl -s -k --key $KEYFILE --cert $CERT http://127.0.0.1:8083/Snh_ConfigDBUUIDCacheReq?search_string=virtual_machine_interface | xmllint --format - > "${HN}_uuid_cache_virtual_machine_interface.xml"
curl -s -k --key $KEYFILE --cert $CERT http://127.0.0.1:8083/Snh_ConfigDBUUIDCacheReq?search_string=virtual_router | xmllint --format - > "${HN}_uuid_cache_virtual_router.xml"
curl -s -k --key $KEYFILE --cert $CERT http://127.0.0.1:8083/Snh_ConfigDBUUIDCacheReq?search_string=routing_instance | xmllint --format - > "${HN}_uuid_cache_routing_instance.xml"
curl -s -k --key $KEYFILE --cert $CERT http://127.0.0.1:8083/Snh_ConfigDBUUIDCacheReq?search_string=virtual_network | xmllint --format - > "${HN}_uuid_cache_virtual_network.xml"



tar -czvf "${DATE}_${HN}_ControllerTraces.tar.gz" *.xml --remove-files