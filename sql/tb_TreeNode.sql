use safebox;

DROP TABLE IF EXISTS tb_TreeNode;

-- MService tree node entity
CREATE TABLE tb_TreeNode
(

    -- unique identifier for an MService tree node
    inbNodeId BIGINT AUTO_INCREMENT NOT NULL,
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
    -- tree node path, with forward slash separators
    chvNodePath VARCHAR(128) NOT NULL,


    PRIMARY KEY (inbNodeId),
    UNIQUE (chvAccountName,chvNodePath)
) ENGINE=InnoDB;

