use safebox;

DROP TABLE IF EXISTS tb_KeyNode;

-- MService key node entity
CREATE TABLE tb_KeyNode
(

    -- unique identifier for an MService key node
    inbKeyId BIGINT AUTO_INCREMENT NOT NULL,
    -- creation date
    dtmCreated DATETIME NOT NULL,
    -- modification date
    dtmModified DATETIME NOT NULL,
    -- deletion date
    dtmDeleted DATETIME NOT NULL,
    -- has record been deleted?
    bitIsDeleted BOOL NOT NULL,
    -- version of this record
    intVersion INT NOT NULL,
    -- unique identifier for an MService tree node
    inbNodeId BIGINT NOT NULL,
    -- unique identifier for an MService data key
    inbDataKeyId BIGINT NOT NULL,
    -- is key node enabled?
    bitIsEnabled BOOL NOT NULL,
    -- key node key name
    chvKeyName VARCHAR(20) NOT NULL,
    -- key node description
    chvKeyDescription VARCHAR(100) NOT NULL,
    -- key node value, encrypted if data_key_id non zero
    binKeyValue VARBINARY(8092) NOT NULL,


    PRIMARY KEY (inbKeyId),
    UNIQUE (inbNodeId,chvKeyName)
) ENGINE=InnoDB;

