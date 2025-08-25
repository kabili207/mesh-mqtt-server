CREATE TABLE users (
    id             INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    display_name   TEXT NULL,
    discord_id     BIGINT NULL,
    mqtt_user      TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    salt           TEXT NOT NULL,
    created        TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT idx_user_mqtt_username UNIQUE (mqtt_user),
    CONSTRAINT idx_user_discord_id UNIQUE (discord_id)
);


CREATE TABLE oauth_tokens (
	user_id       INT NOT NULL PRIMARY KEY,
	token_type    VARCHAR(20),
	access_token  VARCHAR(2048),
	refresh_token VARCHAR(512),
	expiration    TIMESTAMP(2) WITH TIME ZONE,

    CONSTRAINT idx_oauth_user_id UNIQUE (user_id)
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
);