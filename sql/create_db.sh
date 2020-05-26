#!/bin/bash

# 12  create_db.sql  create_tables.sql  permissions.sql

HOST="-h localhost"
PSQL="psql ${HOST} -v ON_ERROR_STOP=1"
set -e
${PSQL} -Upostgres  -f create_db.sql
${PSQL} -Upostgres -f create_tables.sql
PGPASSWORD=keepassmerge ${PSQL} -Ukeepassmerge -h localhost -f permissions.sql
