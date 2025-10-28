package config

import (
	"github.com/kabili207/mesh-mqtt-server/pkg/meshtastic"
	"golang.org/x/oauth2"
)

type Configuration struct {
	ListenAddr    string
	SessionSecret string
	BaseURL       string
	OAuth         struct {
		Discord oauth2.Config
	}
	MeshSettings MeshSettings
	Database     struct {
		User     string
		Password string
		Host     string
		DB       string
	}
}

type MeshSettings struct {
	MqttRoot string
	Channels []MeshChannelDef
	SelfNode struct {
		NodeID    meshtastic.NodeID
		LongName  string
		ShortName string
	}
}

type MeshChannelDef struct {
	Name   string
	Key    string
	Export bool
}
