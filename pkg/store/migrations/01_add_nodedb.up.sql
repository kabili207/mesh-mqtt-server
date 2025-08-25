
CREATE TABLE node_info (
    node_id          BIGINT NOT NULL,
    user_id          INT NOT NULL,
    long_name        VARCHAR(39) NOT NULL DEFAULT '',
    short_name       VARCHAR(4) NOT NULL DEFAULT '',
    node_role        VARCHAR(20) NOT NULL DEFAULT '',
    last_seen        TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_verified    TIMESTAMP WITH TIME ZONE NULL,

    PRIMARY KEY (user_id, node_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,

    -- 0 = unset, 1 = non-lora broadcast, 4294967295 = broadcast, 2 & 3 = reserved
    CONSTRAINT valid_node_id CHECK (node_id >= 4 AND node_id < '4294967295'::BIGINT)
);