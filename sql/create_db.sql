\c postgres

DROP DATABASE IF EXISTS keepassmerge;

-- DROP OWNED BY keepassmerge CASCADE;
DROP USER IF EXISTS keepassmerge;
CREATE USER keepassmerge WITH ENCRYPTED PASSWORD 'keepassmerge';

CREATE DATABASE keepassmerge;
