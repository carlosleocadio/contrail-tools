#!/bin/bash
## CFTS - Carlos Leocadio

HN=$(hostname -s)
DATE=$(date +"%Y%m%dT%H%M%S")

## Get contrail vrouter agent introspect traces

curl -k https://127.0.0.1:8085/Snh_AgentXmppConnectionStatusReq | xmllint --format - > "${HN}_Snh_AgentXmppConnectionStatusReq.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=ControllerRxConfigXmppMessage1 | xmllint --format - > "${HN}_ControllerRxConfigXmppMessage1.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=ControllerRxConfigXmppMessage2 | xmllint --format - > "${HN}_ControllerRxConfigXmppMessage2.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=ControllerRxRouteXmppMessage1 | xmllint --format - > "${HN}_ControllerRxRouteXmppMessage1.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=ControllerRxRouteXmppMessage2 | xmllint --format - > "${HN}_ControllerRxRouteXmppMessage2.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=ControllerTxXmppMessage_1 | xmllint --format - > "${HN}_ControllerTxXmppMessage_1.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=ControllerTxXmppMessage_2 | xmllint --format - > "${HN}_ControllerTxXmppMessage_2.xml"

curl -k https://127.0.0.1:8085/Snh_KInterfaceReq?if_id | xmllint --format - > "${HN}_Snh_KInterfaceReq.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=KSync%20Interface | xmllint --format - > "${HN}_KSyncInterface.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=KSync%20Route | xmllint --format - > "${HN}_KSyncRoute.xml"

curl -k https://127.0.0.1:8085/Snh_NhListReq | xmllint --format - > "${HN}_Snh_NhListReq.xml"

curl -k https://127.0.0.1:8085/Snh_KDropStatsReq | xmllint --format - > "${HN}_Snh_KDropStatsReq.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=OperRoute | xmllint --format - > "${HN}_OperRoute.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=Flow | xmllint --format - > "${HN}_Flow.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=Oper%20db.nexthop.0 | xmllint --format - > "${HN}_OperDBnh.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=KSync%20Nexthop | xmllint --format - > "${HN}_KsyncNexthop.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=KSync%20Vrf | xmllint --format - > "${HN}_KSyncVrf.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=KSync%20VrfAssign | xmllint --format - > "${HN}_KSyncVrfAssign.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=KSync%20BridgeRouteTable | xmllint --format - > "${HN}_KsyncBridgeRouteTable.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=Oper%20db.interface.0 | xmllint --format - > "${HN}_OperDBiface.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=RouteMplsData | xmllint --format - > "${HN}_RouteMplsData.xml"

curl -k https://127.0.0.1:8085/Snh_SandeshTraceRequest?x=PathPreference | xmllint --format - > "${HN}_PathPreference.xml"

tar -czvf "${DATE}_${HN}_VrAgentTraces.tar.gz" *.xml --remove-files
