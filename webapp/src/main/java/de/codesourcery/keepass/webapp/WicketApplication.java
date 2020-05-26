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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.wicket.Component;
import org.apache.wicket.Page;
import org.apache.wicket.RestartResponseAtInterceptPageException;
import org.apache.wicket.application.IComponentInstantiationListener;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.request.cycle.RequestCycle;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * Web application entry point.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class WicketApplication extends WebApplication
{
    private static final Logger LOG = LogManager.getLogger( WicketApplication.class );

    private final Configuration config;
    private final CertCheck certCheck;

    public WicketApplication() throws IOException
    {
        config = Configuration.getInstance();
        certCheck = new CertCheck(config);
    }

    @Override
    public Class<? extends Page> getHomePage()
    {
        return HomePage.class;
    }

    @Override
    protected void init()
    {
        super.init();

        getComponentInstantiationListeners().add(component ->
        {
            if (component.getClass().getAnnotation(Protected.class) != null)
            {
                final HttpServletRequest request = (HttpServletRequest) RequestCycle.get().getRequest().getContainerRequest();
                final X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
                if ( ! certCheck.isValid(certs))
                {
                    if ( LOG.isDebugEnabled() ) {
                        LOG.warn("onInstantiation(): Denying client "+request.getRemoteAddr()+" access to component "+component);
                    }
                    throw new RestartResponseAtInterceptPageException(AccessDeniedPage.class);
                }
            }
        });
    }
}

