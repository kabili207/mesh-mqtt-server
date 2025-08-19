package hooks

import (
	"math"
	"slices"

	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
	pb "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/generated"
	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/radio"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"google.golang.org/protobuf/proto"
)

func (h *MeshtasticHook) TryProcessMeshPacket(client *models.ClientDetails, env *pb.ServiceEnvelope) bool {

	pkt := env.GetPacket()
	if pkt == nil {
		return false
	}
	shouldReencrypt := true
	switch pkt.GetPayloadVariant().(type) {
	case *pb.MeshPacket_Decoded:
		shouldReencrypt = false
	}
	decoded, err := radio.TryDecode(pkt, radio.DefaultKey)
	if err != nil || decoded == nil {
		return false
	}

	h.processMeshPacket(client, env, decoded)

	if !shouldReencrypt {
		pkt.PayloadVariant = &pb.MeshPacket_Decoded{
			Decoded: decoded,
		}
	} else {
		rawData, err := proto.Marshal(decoded)
		if err != nil {
			return false
		}
		rawData, err = radio.XOR(rawData, radio.DefaultKey, pkt.Id, pkt.From)
		pkt.PayloadVariant = &pb.MeshPacket_Encrypted{
			Encrypted: rawData,
		}
	}

	env.Packet = pkt

	return true
}

func (h *MeshtasticHook) processMeshPacket(client *models.ClientDetails, env *pb.ServiceEnvelope, data *pb.Data) {
	switch data.Portnum {
	case pb.PortNum_TRACEROUTE_APP:
		var r = pb.RouteDiscovery{}
		err := proto.Unmarshal(data.Payload, &r)
		if err == nil {
			h.processTraceroute(env, data, &r)
			payload, err := proto.Marshal(&r)
			if err == nil {
				data.Payload = payload
			}
		}
	case pb.PortNum_NODEINFO_APP:
		var u = pb.User{}
		err := proto.Unmarshal(data.Payload, &u)
		if err == nil {
			go h.processNodeInfo(client, env, data, &u)
		}
	}

}

func (h *MeshtasticHook) processNodeInfo(c *models.ClientDetails, env *pb.ServiceEnvelope, data *pb.Data, user *pb.User) {

	if c == nil || !c.IsMeshDevice() {
		// The only time this should happen is when a client sends a node info
		// and immediately loses connection
		return
	}

	if c.NodeDetails == nil {
		// Proxied clients don't always connect with a client ID that contains the node ID
		nid, err := meshtastic.ParseNodeID(env.GatewayId)
		if err != nil {
			return
		}
		c.NodeDetails = &models.NodeInfo{NodeID: nid}
	}

	//clientNode, _ := meshtastic.ParseNodeID(c.NodeID)
	if c.NodeDetails.NodeID.String() != user.Id {
		// Relayed from the mesh, we don't care about it
		return
	}
	c.NodeDetails.LongName = user.LongName
	c.NodeDetails.ShortName = user.ShortName
	if !c.IsVerified {
		if c.VerifyPacketID == 0 {
			go h.TryVerifyNode(c.ClientID, false)
		} else {
			if data.RequestId == c.VerifyPacketID {
				c.IsVerified = true
				h.config.Server.Log.Info("node downlink verified", "node", c.NodeDetails.NodeID, "client", c.ClientID, "topic", c.RootTopic)
			}
		}
	}
	// TODO: Update database record as well
}

func (c *MeshtasticHook) processTraceroute(env *pb.ServiceEnvelope, data *pb.Data, disco *pb.RouteDiscovery) {

	isTowardsDestination := data.RequestId == 0
	c.insertUnknownHops(env.Packet, disco, isTowardsDestination)

	gatewayNode, err := meshtastic.ParseNodeID(env.GetGatewayId())
	if err != nil {
		return
	}

	packet := env.Packet

	// Gateway node isn't always included in the route list, so ensure we add it
	if gatewayNode != 0 && uint32(gatewayNode) != packet.From {
		node := uint32(gatewayNode)
		snr := int32(packet.RxSnr * 4)
		var route *[]uint32
		var snrs *[]int32

		if isTowardsDestination {
			route, snrs = &disco.Route, &disco.SnrTowards
		} else {
			route, snrs = &disco.RouteBack, &disco.SnrBack
		}

		if !slices.Contains(*route, node) {
			*route = append(*route, node)
			*snrs = append(*snrs, snr)
		}
	}
}

func (c *MeshtasticHook) insertUnknownHops(packet *pb.MeshPacket, disco *pb.RouteDiscovery, isTowardsDestination bool) {
	// Insert unknown
	var routeCount = 0
	var snrCount = 0
	var route *[]uint32
	var snrList *[]int32

	if isTowardsDestination {
		routeCount = len(disco.Route)
		snrCount = len(disco.SnrTowards)
		route = &disco.Route
		snrList = &disco.SnrTowards
	} else {
		routeCount = len(disco.RouteBack)
		snrCount = len(disco.SnrBack)
		route = &disco.RouteBack
		snrList = &disco.SnrBack
	}

	if packet.HopStart != 0 && packet.HopLimit <= packet.HopStart {
		hopsTaken := packet.HopStart - packet.HopLimit
		diff := int(hopsTaken) - routeCount

		for i := 0; i < diff; i++ {
			if routeCount < len(*route) {
				r := append(*route, meshtastic.BROADCAST_ID)
				route = &r
				routeCount += 1
			}
		}

		diff = routeCount - snrCount
		for i := 0; i < diff; i++ {
			if snrCount < len(*snrList) {
				s := append(*snrList, math.MinInt8) // Min == SNR Unknown
				snrList = &s
				snrCount += 1
			}
		}
	}
}
