package models

type DiscordUser struct {
	ID            string  `json:"id"`
	Username      string  `json:"username"`
	Descriminator string  `json:"discriminator"`
	GlobalName    *string `json:"global_name"`
	Avatar        *string `json:"avatar"`
}

type DiscordGuildMember struct {
	User    *DiscordUser `json:"user"`
	Nick    *string      `json:"nick"`
	Roles   []string     `json:"roles"`
	Pending *bool        `json:"pending"`
	Flags   int          `json:"flags"`
}
