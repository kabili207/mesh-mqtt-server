package models

import (
	"fmt"
	"sync"

	meshtastic "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
)

type MeshMqttServer interface {
	GetUserClients(userID string) []*ClientDetails
}

type ClientDetails struct {
	UserID         string
	ClientID       string
	NodeDetails    *NodeInfo
	ProxyType      string
	Address        string
	RootTopic      string
	IsVerified     bool
	VerifyPacketID uint32

	VerifyLock sync.RWMutex
}

type NodeInfo struct {
	NodeID    meshtastic.NodeID
	LongName  string
	ShortName string
}

func (c *ClientDetails) IsMeshDevice() bool {
	return c.NodeDetails != nil || c.ProxyType != ""
}

func (c *ClientDetails) GetDisplayName() string {
	if c.NodeDetails != nil {
		return c.NodeDetails.GetDisplayName()
	}
	return c.ClientID
}

func (c *NodeInfo) GetDisplayName() string {
	if c.LongName != "" {
		return fmt.Sprintf("%s (%s)", c.LongName, c.ShortName)
	}
	long, short := c.NodeID.GetDefaultNodeNames()
	return fmt.Sprintf("%s (%s)", long, short)
}
