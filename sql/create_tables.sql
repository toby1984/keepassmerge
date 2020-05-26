\c keepassmerge

BEGIN;

CREATE TYPE log_level AS ENUM ('trace','debug','info','warn','error','fatal');

CREATE SEQUENCE audit_log_seq;
ALTER SEQUENCE audit_log_seq OWNER TO keepassmerge;

CREATE TABLE audit_log (
    audit_log_id bigint PRIMARY KEY DEFAULT nextval('audit_log_seq'), 
    client_ip text NOT NULL,
    creation_time timestamptz NOT NULL,
    level log_level NOT NULL,
    message text NOT NULL
);
ALTER TABLE audit_log OWNER TO keepassmerge;

COMMIT;
