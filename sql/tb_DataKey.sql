use safebox;

DROP TABLE IF EXISTS tb_DataKey;

-- MService data key entity
CREATE TABLE tb_DataKey
(

    -- unique identifier for an MService data key
    inbDataKeyId BIGINT AUTO_INCREMENT NOT NULL,
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
    -- account owning this tree node and associated key nodes
    chvAccountName VARCHAR(20) NOT NULL,
    -- data key name
    chvDataKeyName VARCHAR(20) NOT NULL,
    -- data key description
    chvDataKeyDescription VARCHAR(100) NOT NULL,
    -- encrypted data key
    binDataKey VARBINARY(1024) NOT NULL,


    PRIMARY KEY (inbDataKeyId),
    UNIQUE (chvAccountName,chvDataKeyName)
) ENGINE=InnoDB;

