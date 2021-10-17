/**
 * Copyright 2020 Tobias Gierke <tobias.gierke@code-sourcery.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.codesourcery.keepass.webapp;

import de.codesourcery.keepass.core.util.Logger;
import de.codesourcery.keepass.core.util.LoggerFactory;
import org.apache.commons.lang3.Validate;

import java.io.PrintWriter;
import java.io.Serializable;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.text.MessageFormat;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * DAO for {@link AuditLogEntry} entities.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class AuditLogManager implements Serializable
{
    private final Configuration config;

    /**
     * CREATE TABLE audit_log (
     *     audit_log_id bigint PRIMARY KEY DEFAULT nextval('audit_log_seq'),
     *     client_ip text NOT NULL,
     *     creation_time timestamptz NOT NULL,
     *     level log_level NOT NULL,
     *     message text NOT NULL
     * );
     */
    private static final String TABLE = "audit_log";

    public final class DbLogAppender extends LoggerFactory.ConsoleLogAppender
    {
        private final List<AuditLogEntry> messages = new ArrayList<>();
        private final String clientIP;

        public DbLogAppender(String clientIP)
        {
            Validate.notBlank(clientIP, "remoteIP must not be null or blank");
            this.clientIP = clientIP;
        }

        @Override
        protected void doLog(Logger.Level lvl, Class<?> clazz, String msg, Throwable t)
        {
            final String toAdd = clazz.getSimpleName()+" - "+msg;
            if (t == null)
            {
                messages.add(new AuditLogEntry(clientIP, ZonedDateTime.now(), lvl, toAdd));
            }
            else
            {
                final StringWriter stringWriter = new StringWriter();
                try (PrintWriter w = new PrintWriter(stringWriter))
                {
                    t.printStackTrace(w);
                }
                messages.add(new AuditLogEntry(clientIP, ZonedDateTime.now(), lvl, toAdd + "\n" + stringWriter.getBuffer()));
            }
        }

        @Override
        public void close()
        {
            try
            {
                if ( ! messages.isEmpty() )
                {
                    AuditLogManager.this.createLogEntry(clientIP, messages);
                }
            }
            catch (SQLException t)
            {
                throw new RuntimeException("Failed to write to database",t);
            } finally {
                messages.clear();
            }
        }
    }

    /**
     * Create instance.
     *
     * @param config
     */
    public AuditLogManager(Configuration config) {
        Validate.notNull(config, "config must not be null");
        this.config = config;
    }

    /**
     * Creates a {@link de.codesourcery.keepass.core.util.LoggerFactory.LogAppender}
     * that will write persistent audit-log entries for each of the log messages.
     *
     * For efficiency reasons, log messages will only be persisted
     * when the returned appender is {@link LoggerFactory.LogAppender#close() closed}.
     *
     * @param clientIP client IP to use in all the log messages
     * @return appender
     */
    public LoggerFactory.LogAppender newLogAppender(String clientIP)
    {
        return new DbLogAppender(clientIP);
    }

    /**
     * Check whether the audit log database is accessible.
     *
     * @return <code>true</code> if the database is accessible, otherwise <code>false</code>.
     */
    public boolean testConnectivity() {

        try ( Connection con = getConnection() ) {
            return con.isValid(1 );
        }
        catch (SQLException t)
        {
            return false;
        }
    }

    private Connection getConnection() throws SQLException
    {
        final SQLDbConfig config = this.config.getSQLDatabaseConfig();
        final String url = MessageFormat.format("jdbc:postgresql://{0}:{1}/{2}",
            config.host(),
            Integer.toString( config.port() ),
            config.dbName());

        final String driver = "org.postgresql.Driver";
        try
        {
            Class.forName(driver);
            return DriverManager.getConnection(url, config.user(), config.password() );
        }
        catch (ClassNotFoundException e)
        {
            throw new RuntimeException("Failed to load DB driver '" + driver + "'");
        }
    }

    /**
     * Write one or more persistent log messages for a given client IP.
     *
     * Entries will be persisted once the <code>consumer</code> returns.
     *
     * @param clientIP client IP, must not be <code>null</code> or blank
     * @param consumer consumer
     */
    public void write(String clientIP, Consumer<LoggerFactory.LogAppender> consumer)
    {
        Validate.notNull(consumer, "consumer must not be null");
        try ( final LoggerFactory.LogAppender auditLog = newLogAppender(clientIP) )
        {
            consumer.accept(auditLog);
        }
    }

    private void createLogEntry(String clientIP, List<AuditLogEntry> messages) throws SQLException
    {
        try ( Connection con = getConnection() )
        {
            con.setAutoCommit(false);
            boolean success = false;
            try
            {
                /*
                 * CREATE TABLE audit_log (
                 *     audit_log_id bigint PRIMARY KEY DEFAULT nextval('audit_log_seq'),
                 *     client_ip text NOT NULL,
                 *     creation_time timestamptz NOT NULL,
                 *     level log_level NOT NULL,
                 *     message text NOT NULL
                 * );
                 */
                final String sql = "INSERT INTO "+TABLE+" (client_ip,creation_time,level,message) VALUES (?,?,?,?)";
                try ( final PreparedStatement stmt = con.prepareStatement(sql) )
                {
                    int count = 0;
                    for ( AuditLogEntry s : messages )
                    {
                        String level = switch(s.level()) {

                            case TRACE -> "trace";
                            case DEBUG -> "debug";
                            case INFO, SUCCESS -> "info";
                            case WARNING -> "warn";
                            case ERROR -> "error";
                            default -> throw new RuntimeException("Unhandled case: "+s.level());
                        };
                        stmt.setString(1,s.clientIP());
                        stmt.setTimestamp(2,new Timestamp(s.creationTime().toInstant().toEpochMilli()));
                        stmt.setObject(3,level, Types.OTHER);
                        stmt.setString(4,s.message());
                        stmt.addBatch();
                        count++;
                        if ( ( count % 100 ) == 0 ) {
                            stmt.executeBatch();
                        }
                    }
                    stmt.executeBatch();
                }
                success = true;
            }
            finally
            {
                try
                {
                    con.setAutoCommit(true);
                }
                catch(SQLException e)
                {
                    if ( success ) {
                        throw e;
                    }
                }
            }
        }
    }

    /**
     * Provides paged access to audit log entries sorted descending by creation time.
     *
     * @param offset starting offset (0=latest audit log entry) into the returned result set
     * @param pageSize max number of items to fetch
     * @return paging result
     */
    public ResultPage<AuditLogEntry> getPage(int offset, int pageSize) {

        final List<AuditLogEntry> result = new ArrayList<>();
        final int totalCount;
        try ( Connection con = getConnection() )
        {
            con.setAutoCommit(false);
            try ( Statement s = con.createStatement() )
            {
                final String countQuery = "SELECT count(*) FROM "+TABLE;
                try (ResultSet rs = s.executeQuery(countQuery) )
                {
                       rs.next();
                       totalCount = rs.getInt(1);
                }
                final String resultQuery = "SELECT * FROM "+TABLE+" ORDER BY creation_time DESC OFFSET "+offset+" LIMIT "+pageSize;
                try (ResultSet rs = s.executeQuery(resultQuery ) )
                {
                    while ( rs.next() ) {
                        result.add( new AuditLogEntry(
                            rs.getString("client_ip"),
                            rs.getTimestamp("creation_time").toLocalDateTime().atZone(ZoneId.systemDefault() ),
                            switch( rs.getString("level") ) {
                                case "trace" -> Logger.Level.TRACE;
                                case "debug" -> Logger.Level.DEBUG;
                                case "info" -> Logger.Level.INFO;
                                case "warn" -> Logger.Level.WARNING;
                                case "error" -> Logger.Level.ERROR;
                                default -> throw new IllegalStateException("Unexpected value: " + rs.getString("level"));
                            },
                            rs.getString("message")
                        ) );
                    }
                }
            } finally {
                con.setAutoCommit(true);
            }
        }
        catch (SQLException e)
        {
            throw new RuntimeException(e.getMessage(),e);
        }
        return new ResultPage<>(offset, result, totalCount );
    }
}