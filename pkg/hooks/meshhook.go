package hooks

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
	pb "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/generated"
	"github.com/kabili207/mesh-mqtt-server/pkg/models"
	"github.com/kabili207/mesh-mqtt-server/pkg/store"
	"google.golang.org/protobuf/proto"
)

const (
	meshDevicePattern   = `^(?:Meshtastic(Android|Apple)MqttProxy-)?(![0-9a-f]{8})$`
	unknownProxyPattern = `^Meshtastic(Android|Apple)MqttProxy-(.+)$`
	channelPattern      = `^(msh(?:\/[^\/\n]+?)*)\/2\/e\/(\w+)\/(![a-f0-9]{8})$`

	meshFilter        auth.RString = `msh/US/2/#`
	meshGatewayFilter auth.RString = `msh/US/Gateway/2/#`
)

var (
	meshDeviceRegex   = regexp.MustCompile(meshDevicePattern)
	unknownProxyRegex = regexp.MustCompile(unknownProxyPattern)
	channelRegex      = regexp.MustCompile(channelPattern)
)

// Options contains configuration settings for the hook.
type MeshtasticHookOptions struct {
	Server  *mqtt.Server
	Storage *store.Stores
	NodeID  meshtastic.NodeID

	LongName, ShortName string
}

var _ models.MeshMqttServer = (*MeshtasticHook)(nil)

type MeshtasticHook struct {
	mqtt.HookBase
	config          *MeshtasticHookOptions
	knownClients    map[string]*models.ClientDetails
	clientLock      sync.RWMutex
	currentPacketId uint32
}

func (h *MeshtasticHook) ID() string {
	return "mesht-hook"
}

func (h *MeshtasticHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnConnectAuthenticate,
		mqtt.OnACLCheck,
		mqtt.OnConnect,
		mqtt.OnDisconnect,
		mqtt.OnSubscribed,
		mqtt.OnUnsubscribed,
		mqtt.OnPublished,
		mqtt.OnPublish,
	}, []byte{b})
}

func (h *MeshtasticHook) Init(config any) error {
	h.Log.Info("initialised")
	if _, ok := config.(*MeshtasticHookOptions); !ok && config != nil {
		return mqtt.ErrInvalidConfigType
	}

	h.config = config.(*MeshtasticHookOptions)
	if h.config.Server == nil {
		return mqtt.ErrInvalidConfigType
	}

	if h.config.Storage == nil {
		return mqtt.ErrInvalidConfigType
	}

	h.knownClients = make(map[string]*models.ClientDetails)

	return nil
}

func (h *MeshtasticHook) GetUserClients(mqttUser string) []*models.ClientDetails {
	userClients := []*models.ClientDetails{}
	h.clientLock.RLock()
	defer h.clientLock.RUnlock()

	for _, c := range h.knownClients {
		if c.MqttUserName == mqttUser {
			userClients = append(userClients, c)
		}
	}

	return userClients
}

// OnConnectAuthenticate returns true if the connecting client has rules which provide access
// in the auth ledger.
func (h *MeshtasticHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	user := string(pk.Connect.Username)
	pass := pk.Connect.Password
	clientID := cl.ID
	if user == "admin" {
		return true
	}
	validatedUser := h.validateUser(user, string(pass))
	if validatedUser != nil {

		nodeDetails, proxyType := (*models.NodeInfo)(nil), ""
		if meshDeviceRegex.MatchString(cl.ID) {
			matches := meshDeviceRegex.FindStringSubmatch(cl.ID)
			proxyType = matches[1]
			nid, err := meshtastic.ParseNodeID(matches[2])
			if err == nil {
				nodeDetails, err = h.config.Storage.NodeDB.GetNode(uint32(nid), validatedUser.ID)
				if err != nil {
					h.Log.Error("error loading node info", "node_id", nid, "user_id", validatedUser.ID, "error", err)
				} else if nodeDetails == nil {
					nodeDetails = &models.NodeInfo{NodeID: nid, UserID: validatedUser.ID}
				}
			}
		} else if unknownProxyRegex.MatchString(cl.ID) {
			matches := unknownProxyRegex.FindStringSubmatch(cl.ID)
			proxyType = matches[1]
			//nodeID = matches[2]
		}
		h.clientLock.Lock()
		h.knownClients[clientID] = &models.ClientDetails{
			MqttUserName: user,
			ClientID:     clientID,
			UserID:       validatedUser.ID,
			NodeDetails:  nodeDetails,
			ProxyType:    proxyType,
			Address:      cl.Net.Remote,
		}
		h.clientLock.Unlock()
		h.Log.Info("client authenticated", "username", user, "client", clientID, "node", nodeDetails, "proxy", proxyType)

		if nodeDetails != nil {
			go h.TryVerifyNode(cl.ID, false)
		}
	}

	return validatedUser != nil
}

// OnACLCheck returns true if the connecting client has matching read or write access to subscribe
// or publish to a given topic.
func (h *MeshtasticHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {
	// TODO: Allow admin users to do anything
	if string(cl.Properties.Username) == "admin" {
		return true
	}

	if topic == "will" || topic == "/will" {
		return true
	}

	isMeshTopic := meshFilter.FilterMatches(topic)
	isGatewayTopic := meshGatewayFilter.FilterMatches(topic)
	if !isMeshTopic && !isGatewayTopic {
		return false
	}

	h.clientLock.RLock()
	cd, ok := h.knownClients[cl.ID]
	h.clientLock.RUnlock()
	if !ok {
		h.Log.Warn("unknown client in ACL check",
			"client", cl.ID,
			"username", cd.MqttUserName,
			"topic", topic)
		return false
	}

	if !cd.IsMeshDevice() {
		// Non-mesh devices are only allowed to read
		return !write
	}

	if !isGatewayTopic || cd.ProxyType != "" {
		// Default user ID or proxied nodes are only allowed to write
		return write
	}

	//if strings.HasPrefix(cd.UserID, "mesht-") {
	// TODO: Only allow gateway nodes to read and write
	return true
	//}

	// TODO: Check ACLs for other users

	return false
}

// subscribeCallback handles messages for subscribed topics
func (h *MeshtasticHook) subscribeCallback(cl *mqtt.Client, sub packets.Subscription, pk packets.Packet) {
	h.Log.Info("hook subscribed message", "client", cl.ID, "topic", pk.TopicName)
}

func (h *MeshtasticHook) OnConnect(cl *mqtt.Client, pk packets.Packet) error {
	h.Log.Info("client connected", "client", cl.ID)

	return nil
}

func (h *MeshtasticHook) TryVerifyNode(clientID string, force bool) {
	h.clientLock.RLock()
	cd, _ := h.knownClients[clientID]
	h.clientLock.RUnlock()
	if cd.VerifyPacketID == 0 && (!cd.IsVerified() || force) {
		h.RequestNodeInfo(cd)
	}
}

func (h *MeshtasticHook) RequestNodeInfo(client *models.ClientDetails) {

	if client.NodeDetails == nil || client.RootTopic == "" || !client.VerifyLock.TryLock() {
		return
	}
	defer client.VerifyLock.Unlock()

	unmess := true
	nodeInfo := pb.User{
		Id:         h.config.NodeID.String(),
		LongName:   h.config.LongName,
		ShortName:  h.config.ShortName,
		IsLicensed: false,
		HwModel:    pb.HardwareModel_PRIVATE_HW,
		Role:       pb.Config_DeviceConfig_CLIENT_MUTE,
		//Macaddr:    from.ToMacAddress(),
		PublicKey:      nil,
		IsUnmessagable: &unmess,
	}

	pid, err := h.sendProtoMessage("LongFast", client.RootTopic, &nodeInfo, PacketInfo{
		To:           client.NodeDetails.NodeID,
		PortNum:      pb.PortNum_NODEINFO_APP,
		Encrypted:    PSKEncryption,
		WantResponse: true,
	})
	if err == nil {
		h.config.Server.Log.Info("verification packet sent to node", "node", client.NodeDetails.NodeID, "client", client.ClientID, "topic_root", client.RootTopic)
		client.VerifyPacketID = pid
		time.AfterFunc(5*time.Minute, func() {
			client.VerifyPacketID = 0
		})
	}
}

func (h *MeshtasticHook) OnDisconnect(cl *mqtt.Client, err error, expire bool) {
	h.clientLock.Lock()
	delete(h.knownClients, cl.ID)
	h.clientLock.Unlock()
	if err != nil {
		h.Log.Info("client disconnected", "client", cl.ID, "expire", expire, "error", err)
	} else {
		h.Log.Info("client disconnected", "client", cl.ID, "expire", expire)
	}

}

func (h *MeshtasticHook) OnSubscribed(cl *mqtt.Client, pk packets.Packet, reasonCodes []byte) {
	h.Log.Info(fmt.Sprintf("subscribed qos=%v", reasonCodes), "client", cl.ID, "filters", pk.Filters)
}

func (h *MeshtasticHook) OnUnsubscribed(cl *mqtt.Client, pk packets.Packet) {
	h.Log.Info("unsubscribed", "client", cl.ID, "filters", pk.Filters)
}

func (h *MeshtasticHook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	h.Log.Info("received from client", "client", cl.ID)

	if strings.HasPrefix(pk.TopicName, "msh/") {
		var env pb.ServiceEnvelope
		err := proto.Unmarshal(pk.Payload, &env)
		if err != nil {
			// Do not allow non-meshtastic payloads in the msh tree
			h.Log.Error("received non-mesh payload from client", "client", cl.ID, "payload", string(pk.Payload))
			return pk, err
		}
		h.clientLock.RLock()
		cd, ok := h.knownClients[cl.ID]
		h.clientLock.RUnlock()
		if ok && cd.IsMeshDevice() {
			h.TrySetRootTopic(cd, pk.TopicName)
		}
		h.TryProcessMeshPacket(cd, &env)
		payload, err := proto.Marshal(&env)
		if err != nil {
			// Do not allow non-meshtastic payloads in the msh tree
			h.Log.Error("error re-marshalling service packet", "client", cl.ID)
			return pk, err
		}
		pkx := pk
		pkx.Payload = payload
		// TODO: If gateway is not verified, push to non gateway topic instead
		return pkx, nil

	}

	return pk, nil
}

func (h *MeshtasticHook) TrySetRootTopic(cd *models.ClientDetails, topic string) {
	matches := channelRegex.FindStringSubmatch(topic)
	if len(matches) > 0 {
		cd.RootTopic = matches[1]
		if cd.NodeDetails == nil {
			// Proxied clients don't always connect with a client ID that contains the node ID
			nid, err := meshtastic.ParseNodeID(matches[3])
			if err != nil {
				return
			}
			nodeDetails, err := h.config.Storage.NodeDB.GetNode(uint32(nid), cd.UserID)
			if err != nil {
				h.Log.Error("error loading node info", "node_id", nid, "user_id", cd.UserID, "error", err)
			} else if nodeDetails == nil {
				nodeDetails = &models.NodeInfo{NodeID: nid, UserID: cd.UserID}
			}
			cd.NodeDetails = nodeDetails
		}
		go h.TryVerifyNode(cd.ClientID, false)
	}
}

func (h *MeshtasticHook) OnPublished(cl *mqtt.Client, pk packets.Packet) {
	h.Log.Info("published to client", "client", cl.ID)
}
