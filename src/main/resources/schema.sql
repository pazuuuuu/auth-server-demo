-- 利用者（com.example.authserver.data.User）。以前は Hibernate の ddl-auto=update で作っていた
CREATE TABLE IF NOT EXISTS users (
    username varchar(255) NOT NULL,
    password varchar(255),
    enabled boolean NOT NULL,
    PRIMARY KEY (username)
);

CREATE TABLE IF NOT EXISTS oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamp DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes text DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value text DEFAULT NULL,
    authorization_code_issued_at timestamp DEFAULT NULL,
    authorization_code_expires_at timestamp DEFAULT NULL,
    authorization_code_metadata text DEFAULT NULL,
    access_token_value text DEFAULT NULL,
    access_token_issued_at timestamp DEFAULT NULL,
    access_token_expires_at timestamp DEFAULT NULL,
    access_token_metadata text DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value text DEFAULT NULL,
    oidc_id_token_issued_at timestamp DEFAULT NULL,
    oidc_id_token_expires_at timestamp DEFAULT NULL,
    oidc_id_token_metadata text DEFAULT NULL,
    refresh_token_value text DEFAULT NULL,
    refresh_token_issued_at timestamp DEFAULT NULL,
    refresh_token_expires_at timestamp DEFAULT NULL,
    refresh_token_metadata text DEFAULT NULL,
    user_code_value text DEFAULT NULL,
    user_code_issued_at timestamp DEFAULT NULL,
    user_code_expires_at timestamp DEFAULT NULL,
    user_code_metadata text DEFAULT NULL,
    device_code_value text DEFAULT NULL,
    device_code_issued_at timestamp DEFAULT NULL,
    device_code_expires_at timestamp DEFAULT NULL,
    device_code_metadata text DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

-- パスワード再設定トークン（PasswordResetTokenRepository）。トークンそのものではなく SHA-256 のハッシュを置く（docs/SLO.md §7）
CREATE TABLE IF NOT EXISTS password_reset_token (
    token_hash varchar(64) NOT NULL,
    username varchar(255) NOT NULL,
    expires_at timestamp NOT NULL,
    PRIMARY KEY (token_hash)
);

-- パスキー（JdbcPublicKeyCredentialUserEntityRepository・JdbcUserCredentialRepository）。Spring Security 6.5 の標準スキーマと同じ形
CREATE TABLE IF NOT EXISTS user_entities (
    id varchar(1000) NOT NULL,
    name varchar(100) NOT NULL,
    display_name varchar(200),
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS user_credentials (
    credential_id varchar(1000) NOT NULL,
    user_entity_user_id varchar(1000) NOT NULL,
    public_key bytea NOT NULL,
    signature_count bigint,
    uv_initialized boolean,
    backup_eligible boolean NOT NULL,
    authenticator_transports varchar(1000),
    public_key_credential_type varchar(100),
    backup_state boolean NOT NULL,
    attestation_object bytea,
    attestation_client_data_json bytea,
    created timestamp,
    last_used timestamp,
    label varchar(1000) NOT NULL,
    PRIMARY KEY (credential_id)
);
