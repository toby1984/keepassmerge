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

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.mail.internet.InternetAddress;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Application configuration (singleton).
 *
 * By default, configuration is loaded from a {@link #CONFIG_FILE_CLASSPATH file on the classpath} but this
 * may be overridden to using a file on the local filesystem instead by passing the
 * {@link #SYS_PROP_CONFIG_OVERRIDE JVM property} to the JVM.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class Configuration extends ConfigHelper implements Serializable
{
    private static final Logger LOG = LogManager.getLogger( Configuration.class );

    private static final AtomicReference<Configuration> configuration= new AtomicReference<>();

    /**
     * Default classpath location of configuration file.
     */
    public static final String CONFIG_FILE_CLASSPATH = "/keePassMerge.properties";

    /** Path to configuration file on filesystem */
    public static final String SYS_PROP_CONFIG_OVERRIDE = "keepassmerge.config";

    /** path to .kdbx file that all changes should get merged into
     * This is also the file that can be downloaded via the web UI
    */
    public static final ConfigProperty<File> PROP_MERGE_TARGET = ConfigProperty.of("merge.target", FILE_TYPE);

    /** Folder for storage of temporary files */
    public static final ConfigProperty<File> PROP_TEMP_FOLDER = ConfigProperty.of("temp.folder", DIRECTORY_TYPE);

    public static final ConfigProperty<Duration> PROP_MIN_KEY_DERIVATION_TIME =
        ConfigProperty.of("outerEnc.minKeyDerivationTime",DURATION_MILLIS_TYPE,null);

    // SSL client authentication properties
    public static final ConfigProperty<File> PROP_SSL_CLIENT_AUTH_KEYSTORE =
        ConfigProperty.of("auth.ssl.keystore",FILE_TYPE);

    public static final ConfigProperty<String> PROP_SSL_CLIENT_AUTH_KEYSTORE_TYPE =
        ConfigProperty.of("auth.ssl.keystore.type",STRING_TYPE);

    public static final ConfigProperty<String> PROP_SSL_CLIENT_AUTH_KEYSTORE_PASSWORD =
        ConfigProperty.of("auth.ssl.keystore.password",STRING_TYPE);

    public static final ConfigProperty<String> PROP_SSL_CLIENT_AUTH_CA_CERT_ALIAS =
        ConfigProperty.of("auth.ssl.caCertAlias",STRING_TYPE);

    // database connection properties
    public static final ConfigProperty<String> PROP_DB_HOST = ConfigProperty.of("db.host",STRING_TYPE);
    public static final ConfigProperty<String> PROP_DB_NAME = ConfigProperty.of("db.name",STRING_TYPE);
    public static final ConfigProperty<Integer> PROP_DB_PORT = ConfigProperty.of("db.port",INTEGER_TYPE,5432);
    public static final ConfigProperty<String> PROP_DB_USER = ConfigProperty.of("db.user",STRING_TYPE);
    public static final ConfigProperty<String> PROP_DB_PASSWORD = ConfigProperty.of("db.password",STRING_TYPE);

    // email properties
    public static final ConfigProperty<String> PROP_SMTP_HOST = ConfigProperty.of("smtp.host",STRING_TYPE);
    public static final ConfigProperty<Integer> PROP_SMTP_PORT = ConfigProperty.of("smtp.port",INTEGER_TYPE,25);
    public static final ConfigProperty<Boolean> PROP_SMTP_USE_SSL = ConfigProperty.of("smtp.useSSL",BOOLEAN_TYPE,false);
    public static final ConfigProperty<Boolean> PROP_SMTP_USE_TLS = ConfigProperty.of("smtp.useTLS",BOOLEAN_TYPE,false);
    public static final ConfigProperty<InternetAddress[]> PROP_SMTP_SENDER = ConfigProperty.of("smtp.senderAddress",EMAIL_TYPE);
    public static final ConfigProperty<InternetAddress[]> PROP_SMTP_RECIPIENTS = ConfigProperty.of("smtp.recipientAddresses",EMAIL_TYPE);
    public static final ConfigProperty<Duration> PROP_SMTP_TIMEOUT = ConfigProperty.of("smtp.timeout",DURATION_SECONDS_TYPE, Duration.ofSeconds(15));
    public static final ConfigProperty<Boolean> PROP_SMTP_USE_AUTHENTICATION = ConfigProperty.of("smtp.useAuthentication",BOOLEAN_TYPE,false);
    public static final ConfigProperty<String> PROP_SMTP_AUTH_USER = ConfigProperty.of("smtp.user",STRING_TYPE,null);
    public static final ConfigProperty<String> PROP_SMTP_AUTH_PASSWORD= ConfigProperty.of("smtp.password",STRING_TYPE,null);

    private File mergeTarget;
    private File tempFolder;
    private SQLDbConfig sqlConfig;
    private MailConfiguration mailConfiguration;
    private Duration minKeyDerivationTime;
    private X509Certificate caCertificate;

    /**
     * Returns the application configuration.
     *
     * @return configuration
     * @throws IOException when loading the configuration failed
     */
    public static Configuration getInstance() throws IOException
    {
        if ( configuration.get() == null ) {
            configuration.compareAndSet(null, new Configuration() );
        }
        return configuration.get();
    }

    private Configuration() throws IOException
    {
        final PropertiesWithLocation properties = loadProperties();

        mergeTarget = PROP_MERGE_TARGET.readFrom(properties);
        if ( ! mergeTarget.canRead() || ! mergeTarget.canWrite() ) {
            throw new IOException("Expected merge target " + mergeTarget.getAbsolutePath() + " to be a readable, writable, regular file");
        }
        tempFolder = PROP_TEMP_FOLDER.readFrom(properties);

        minKeyDerivationTime = PROP_MIN_KEY_DERIVATION_TIME.readFrom(properties);

        caCertificate = loadCACertificate(properties);

        sqlConfig = new SQLDbConfig(
            PROP_DB_NAME.readFrom(properties),
            PROP_DB_HOST.readFrom(properties),
            PROP_DB_PORT.readFrom(properties),
            PROP_DB_USER.readFrom(properties),
            PROP_DB_PASSWORD.readFrom(properties)
        );

        mailConfiguration = new MailConfiguration(
            PROP_SMTP_HOST.readFrom(properties),
            PROP_SMTP_PORT.readFrom(properties),
            PROP_SMTP_USE_SSL.readFrom(properties),
            PROP_SMTP_USE_TLS.readFrom(properties),
            PROP_SMTP_SENDER.readFrom(properties)[0],
            PROP_SMTP_RECIPIENTS.readFrom(properties),
            PROP_SMTP_TIMEOUT.readFrom(properties),
            PROP_SMTP_USE_AUTHENTICATION.readFrom(properties),
            PROP_SMTP_AUTH_USER.readFrom(properties),
            PROP_SMTP_AUTH_PASSWORD.readFrom(properties)
        );
        LOG.info("Configuration(): Connecting to "+sqlConfig);
    }

    private static X509Certificate loadCACertificate(PropertiesWithLocation properties)
    {
        final String keyStoreType = PROP_SSL_CLIENT_AUTH_KEYSTORE_TYPE.readFrom(properties);
        final KeyStore keystore;
        try
        {
            keystore = KeyStore.getInstance(keyStoreType);
        }
        catch (KeyStoreException e)
        {
            throw new RuntimeException("Failed to create keystore with type '" + keyStoreType + "'", e);
        }

        final File keyStoreLocation = PROP_SSL_CLIENT_AUTH_KEYSTORE.readFrom(properties);
        try (InputStream in = new FileInputStream(keyStoreLocation) )
        {
            final String keyStorePasswd = PROP_SSL_CLIENT_AUTH_KEYSTORE_PASSWORD.readFrom(properties);
            keystore.load(in,keyStorePasswd.toCharArray());
        }
        catch (Exception e)
        {
            throw new RuntimeException("Failed to load keystore '"+keyStoreLocation.getAbsolutePath()+"'",e);
        }

        final String caCertAlias = PROP_SSL_CLIENT_AUTH_CA_CERT_ALIAS.readFrom(properties);
        try
        {
            final X509Certificate caCertificate = (X509Certificate) keystore.getCertificate(caCertAlias);
            if ( caCertificate == null ) {
                throw new RuntimeException("CA certificate with alias '"+caCertAlias+"' not found in keystore '"+keyStoreLocation.getAbsolutePath()+"'");
            }
            return caCertificate;
        }
        catch (KeyStoreException e)
        {
            throw new RuntimeException("Failed to read certificate '"+caCertAlias+"' from keystore '"+keyStoreLocation.getAbsolutePath()+"'",e);
        }
    }

    private PropertiesWithLocation loadProperties() throws IOException
    {
        final Properties properties = new Properties();
        final String location;

        final String override = System.getProperty(SYS_PROP_CONFIG_OVERRIDE,null);
        if (StringUtils.isBlank(override))
        {
            location = "classpath:"+CONFIG_FILE_CLASSPATH;
            LOG.info("loadProperties(): Loading configuration from "+location);
            try ( InputStream in = Configuration.class.getResourceAsStream(CONFIG_FILE_CLASSPATH) )
            {
                if ( in == null ) {
                    throw new FileNotFoundException("Failed to load configuration file from "+location);
                }
                properties.load(in);
            }
            return new PropertiesWithLocation(properties,location);
        }
        location = "file://"+override+" (from "+SYS_PROP_CONFIG_OVERRIDE+")";
        LOG.info("loadProperties(): Loading configuration from "+location);
        try ( InputStream in = new FileInputStream(override) )
        {
            properties.load(in);
        }
        return new PropertiesWithLocation(properties,location);
    }

    /**
     * Returns the .kdbx file location to merge changes into.
     *
     * This is also the file that can be downloaded via the web UI.
     *
     * @return .kdbx file location
     */
    public File getMergeTarget()
    {
        return mergeTarget;
    }

    /**
     * Returns the temporary folder to use.
     *
     * @return folder
     */
    public File getTempFolder()
    {
        return tempFolder;
    }

    /**
     * Returns the SQL database configuration.
     *
     * @return config
     */
    public SQLDbConfig getSQLDatabaseConfig()
    {
        return sqlConfig;
    }

    public MailConfiguration getMailConfiguration() {
        return mailConfiguration;
    }

    public Optional<Duration> getMinKeyDerivationTime()
    {
        return Optional.ofNullable( minKeyDerivationTime );
    }

    public X509Certificate getCACertificate() {
        return caCertificate;
    }
}