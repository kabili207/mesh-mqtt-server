package models

import (
	"fmt"
	"sync"
	"time"

	meshtastic "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
	pb "github.com/kabili207/mesh-mqtt-server/pkg/meshtastic/generated"
)

const (
	MaxValidationAge = 3 * 24 * time.Hour
)

type MeshMqttServer interface {
	GetUserClients(userID string) []*ClientDetails
}

type ClientDetails struct {
	MqttUserName   string
	UserID         int
	ClientID       string
	NodeDetails    *NodeInfo
	ProxyType      string
	Address        string
	RootTopic      string
	VerifyPacketID uint32

	VerifyLock sync.RWMutex
}

type NodeInfo struct {
	NodeID       meshtastic.NodeID `db:"node_id"`
	UserID       int               `db:"user_id"`
	LongName     string            `db:"long_name"`
	ShortName    string            `db:"short_name"`
	NodeRole     string            `db:"node_role"`
	LastSeen     *time.Time        `db:"last_seen"`
	VerifiedDate *time.Time        `db:"last_verified"`
}

func (c *ClientDetails) IsMeshDevice() bool {
	return c.NodeDetails != nil || c.ProxyType != ""
}

func (c *ClientDetails) GetDisplayName() string {
	if c.NodeDetails != nil {
		return c.NodeDetails.GetDisplayName()
	}
	if c.IsMeshDevice() {
		return "unknown"
	}
	return c.ClientID
}

func (c *ClientDetails) IsVerified() bool {
	return c.NodeDetails != nil && c.NodeDetails.IsVerified()
}

func (c *ClientDetails) IsValidGateway() bool {
	return c.NodeDetails != nil && c.IsVerified() &&
		c.NodeDetails.NodeRole != pb.Config_DeviceConfig_CLIENT_MUTE.String()
}

func (c *ClientDetails) SyncUserID() {
	if c.NodeDetails != nil {
		c.NodeDetails.UserID = c.UserID
	}
}

func (c *NodeInfo) GetDisplayName() string {
	if c.LongName != "" {
		return fmt.Sprintf("%s (%s)", c.LongName, c.ShortName)
	}
	long, short := c.NodeID.GetDefaultNodeNames()
	return fmt.Sprintf("%s (%s)", long, short)
}

func (c *NodeInfo) IsVerified() bool {
	if c.VerifiedDate != nil {
		expireDate := c.VerifiedDate.Add(MaxValidationAge)
		return time.Now().Before(expireDate)
	}
	return false
}
