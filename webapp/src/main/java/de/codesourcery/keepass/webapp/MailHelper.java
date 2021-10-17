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

import org.apache.commons.lang3.Validate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Helper class to send e-mail (singleton).
 * @author tobias.gierke@code-sourcery.de
 */
public class MailHelper
{
    private static final Logger LOG = LogManager.getLogger( MailHelper.class );

    private static final AtomicReference<MailHelper> INSTANCE = new AtomicReference<>();

    private final Configuration config;

    /**
     * Return the s
     * @return
     */
    public static MailHelper getInstance()
    {
        final MailHelper result = INSTANCE.get();
        if ( result == null )
        {
            try
            {
                final MailHelper tmp = new MailHelper(Configuration.getInstance());
                return INSTANCE.compareAndSet(null,tmp) ? tmp : INSTANCE.get();
            }
            catch (IOException e)
            {
                throw new RuntimeException("Initialization failed",e);
            }
        }
        return result;
    }

    private MailHelper(Configuration config) {
        this.config = config;
    }

    /**
     * Send mail.
     *
     * @param subject subject
     * @param body body
     * @return <code>true</code> if sending the mail was successful, false otherwise.
     */
    public boolean sendMail(String subject, String body)
    {
        Validate.notBlank( subject, "subject must not be null or blank");
        Validate.notBlank( body, "body must not be null or blank");
        try
        {
            final Properties props = new Properties();

            final MailConfiguration mailConfig = config.getMailConfiguration();

            if ( mailConfig.useSSL() ) {
                props.put("mail.smtp.ssl.enable","true");
            } else if ( mailConfig.useTLS() ) {
                props.put("mail.smtp.starttls.enable", "true");
                props.put("mail.smtp.starttls.required", "true");
            }

            props.put("mail.smtp.host", mailConfig.smtpHost());
            props.put("mail.smtp.port", mailConfig.smtpPort());

            if ( mailConfig.timeout() != null )
            {
                final String timeout = Long.toString( mailConfig.timeout().toMillis());
                props.put("mail.smtp.connectiontimeout", timeout);
                props.put("mail.smtp.timeout", timeout);
                props.put("mail.smtp.writetimeout", timeout);
            }

            final Session session;
            if ( mailConfig.useAuthentication() ) {
                props.put("mail.smtp.auth", "true");
                props.put("mail.smtp.user", mailConfig.serverUser());

                final Authenticator auth = new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication()
                    {
                        return new PasswordAuthentication(mailConfig.serverUser(), mailConfig.serverPassword());
                    }
                };
                session = Session.getInstance(props, auth );
            } else {
                session = Session.getInstance(props);
            }

            final Message message = new MimeMessage(session);
            message.setFrom(mailConfig.senderAddress());
            message.setRecipients(Message.RecipientType.TO, mailConfig.recipientAddresses() );
            message.setSubject(subject);
            message.setSentDate(new Date());
            message.setText(body);
            Transport.send(message);
            return true;
        }
        catch(Exception e) {
            LOG.error("sendMail(): Failed",e);
        }
        return false;
    }
}