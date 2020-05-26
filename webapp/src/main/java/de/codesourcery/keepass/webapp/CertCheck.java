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

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.Validate;
import org.apache.logging.log4j.LogManager;

import java.security.cert.X509Certificate;

/**
 * Checks whether a set of X.509 certificates contains any
 * certificate that was signed by our CA.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class CertCheck
{
    private static final org.apache.logging.log4j.Logger LOG = LogManager.getLogger( CertCheck.class );

    private final Configuration configuration;

    public CertCheck(Configuration configuration)
    {
        Validate.notNull(configuration, "configuration must not be null");
        this.configuration = configuration;
    }

    public boolean isValid(java.security.cert.X509Certificate[] certs)
    {
        if (ArrayUtils.isEmpty(certs) ) {
            LOG.debug("verify(): No certificates to check.");
            return false;
        }
        for (X509Certificate cert : certs)
        {
            try
            {
                cert.verify(configuration.getCACertificate().getPublicKey());
                cert.checkValidity();
                return true;
            }
            catch (Exception e)
            {
                if ( LOG.isDebugEnabled() ) {
                    LOG.debug("verify(): Failed to validate "+cert,e);
                }
            }
        }
        return false;
    }
}