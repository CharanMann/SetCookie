/*
 * Copyright © 2019 ForgeRock, AS.
 *
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Portions Copyrighted 2019 Charan Mann
 *
 * SetCookie: Created by Charan Mann on 2019-05-24 , 08:57.
 */

package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.dpro.session.SessionException;
import org.forgerock.http.header.SetCookieHeader;
import org.forgerock.http.protocol.Cookie;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openam.auth.node.api.TreeHook;
import org.forgerock.openam.auth.node.api.TreeHookException;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.session.Session;
import org.forgerock.openam.utils.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@TreeHook.Metadata(configClass = SetCookie.Config.class)
public class SetCookieTreeHook implements TreeHook {

    private static final String SET_COOKIE_HEADER_KEY = "Set-Cookie";
    private static final String DEFAULT_PATH = "/";

    private final Session session;
    private final Response response;
    private final Request request;
    private final SetCookie.Config config;
    private final Logger logger = LoggerFactory.getLogger(SetCookieTreeHook.class);
    private CoreWrapper coreWrapper;

    /**
     * The CreatePersistentCookieTreeHook constructor.
     *
     * @param session  the session.
     * @param response the response.
     * @param request  the request.
     * @param config   the config for creating a jwt.
     */
    @Inject
    public SetCookieTreeHook(CoreWrapper coreWrapper, @Assisted Session session, @Assisted Response response,
                             @Assisted SetCookie.Config config, @Assisted Request request) {
        this.coreWrapper = coreWrapper;
        this.session = session;
        this.response = response;
        this.config = config;
        this.request = request;
    }

    @Override
    public void accept() throws TreeHookException {
        logger.debug("SetCookieTreeHook started");

        String cookieValue;
        try {
            cookieValue = session.getProperty(config.sessionProperty());
        } catch (SessionException e) {
            throw new TreeHookException(e);
        }
        Date expiry = new Date(Time.currentTimeMillis() + TimeUnit.HOURS.toMillis(config.maxLife().to(TimeUnit.HOURS)));
        setCookieOnResponse(response, request, config.cookieName(), cookieValue, expiry, config.useSecureCookie(),
                config.useHttpOnlyCookie());
    }

    /**
     * Sets a persistent cookie on a Response.
     *
     * @param response    the response.
     * @param cookieName  the name used as the persistent cookie.
     * @param cookieValue the value - usually a jwt.
     * @param isSecure    if true it adds the secure setting, for SSL only responses.
     * @param isHttpOnly  if true it adds the http only setting.
     */
    private void setCookieOnResponse(Response response, Request request, String cookieName, String cookieValue,
                                     Date expiryDate, boolean isSecure, boolean isHttpOnly) {

        logger.debug("setCookieOnResponse");
        Collection<String> domains = coreWrapper.getCookieDomainsForRequest(request);
        if (!domains.isEmpty()) {
            logger.debug("domains is not empty");
            for (String domain : domains) {
                Cookie cookie = createCookie(cookieName, cookieValue, domain, expiryDate, isSecure, isHttpOnly);
                SetCookieHeader header = new SetCookieHeader(Collections.singletonList(cookie));
                for (String headerValue : header.getValues()) {
                    response.getHeaders().put(SET_COOKIE_HEADER_KEY, headerValue);
                }
            }
        } else {
            Cookie cookie = createCookie(cookieName, cookieValue, null, expiryDate, isSecure, isHttpOnly);
            response.getHeaders().put(SET_COOKIE_HEADER_KEY, cookie);
        }
    }


    private Cookie createCookie(String name, String value, String domain, Date expiryDate, boolean isSecure,
                                boolean isHttpOnly) {
        return new Cookie()
                .setName(name)
                .setValue(value)
                .setPath(DEFAULT_PATH)
                .setDomain(domain)
                .setExpires(expiryDate)
                .setSecure(isSecure)
                .setHttpOnly(isHttpOnly);
    }
}