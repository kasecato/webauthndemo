CREATE TABLE credential (
  id                         BIGINT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
  user_id                    BIGINT UNSIGNED NOT NULL,
  date                       TIMESTAMP       NOT NULL             DEFAULT CURRENT_TIMESTAMP,
  sign_count                 INT UNSIGNED    NOT NULL             DEFAULT 0,
  public_key_credential_id   VARCHAR(256)    NOT NULL,
  raw_id                     BLOB            NOT NULL,
  attestation_object_bytes   BLOB            NOT NULL
)
  ENGINE = InnoDB;

CREATE TABLE session_data (
  id        BIGINT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
  user_id   BIGINT UNSIGNED NOT NULL,
  challenge VARCHAR(256)    NOT NULL,
  origin    VARCHAR(256)    NOT NULL,
  created   TIMESTAMP       NOT NULL             DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE
)
  ENGINE = InnoDB;
