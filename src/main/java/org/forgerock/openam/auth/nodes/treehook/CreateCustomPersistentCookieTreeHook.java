/*
 * Copyright 2017-2018 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes.treehook;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.dpro.session.SessionException;
import com.sun.identity.authentication.util.ISAuthConstants;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openam.auth.node.api.TreeHook;
import org.forgerock.openam.auth.node.api.TreeHookException;
import org.forgerock.openam.auth.nodes.SetCustomPersistentCookieNode;
import org.forgerock.openam.auth.nodes.jwt.InvalidPersistentJwtException;
import org.forgerock.openam.auth.nodes.jwt.PersistentJwtClaimsHandler;
import org.forgerock.openam.auth.nodes.jwt.PersistentJwtStringSupplier;
import org.forgerock.openam.session.Session;
import org.forgerock.util.time.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * A TreeHook for creating persistent cookies.
 */
@TreeHook.Metadata(configClass = SetCustomPersistentCookieNode.Config.class)
public class CreateCustomPersistentCookieTreeHook implements TreeHook {

    private static final String SERVICE_SESSION_PROPERTY = "Service";
    private final Session session;
    private final Response response;
    private final Request request;
    private final SetCustomPersistentCookieNode.Config config;
    private final PersistentJwtStringSupplier persistentJwtStringSupplier;
    private final PersistentJwtClaimsHandler persistentJwtClaimsHandler;
    private final PersistentCookieResponseHandler persistentCookieResponseHandler;
    private final Logger logger = LoggerFactory.getLogger("amAuth");

    /**
     * The CreatePersistentCookieTreeHook constructor.
     *
     * @param session the session.
     * @param response the response.
     * @param request the request.
     * @param config the config for creating a jwt.
     */
    @Inject
    public CreateCustomPersistentCookieTreeHook(@Assisted Session session, @Assisted Response response,
                                          @Assisted SetCustomPersistentCookieNode.Config config, @Assisted Request request) {
        this.session = session;
        this.response = response;
        this.config = config;
        this.request = request;
        this.persistentJwtStringSupplier = InjectorHolder.getInstance(PersistentJwtStringSupplier.class);
        this.persistentCookieResponseHandler = InjectorHolder.getInstance(PersistentCookieResponseHandler.class);
        this.persistentJwtClaimsHandler = new PersistentJwtClaimsHandler();
    }

    @Override
    public void accept() throws TreeHookException {
        logger.debug("creating persistent cookie tree hook");
        String clientId, service, clientIP;
        try {
            clientId = session.getClientID();
            service = session.getProperty(SERVICE_SESSION_PROPERTY);
            clientIP = session.getProperty(ISAuthConstants.HOST);
            logger.debug("clientId {} \n service {} \n clientIP {}", clientId, service, clientIP);
        } catch (SessionException e) {
            logger.error("Tree hook creation exception", e);
            throw new TreeHookException(e);
        }
        String orgName = PersistentCookieResponseHandler.getOrgName(response);
        Map<String, String> authContext = persistentJwtClaimsHandler.createJwtAuthContext(orgName, clientId, service,
                clientIP);
        String jwtString;

        Set<String> attributes = config.userAttributes();

        try {
            jwtString = persistentJwtStringSupplier.createJwtString(orgName, authContext, config.maxLife()
                .to(TimeUnit.HOURS), config.idleTimeout().to(TimeUnit.HOURS), String.valueOf(config.hmacSigningKey()));
        } catch (InvalidPersistentJwtException e) {
            logger.error("Error creating jwt string", e);
            throw new TreeHookException(e);
        }

        if (jwtString != null && !jwtString.isEmpty()) {
            long expiryInMillis = TimeService.SYSTEM.now() + config.maxLife().to(TimeUnit.MILLISECONDS);
            persistentCookieResponseHandler.setCookieOnResponse(response, request, config.persistentCookieName(),
                    jwtString, new Date(expiryInMillis), config.useSecureCookie(), config.useHttpOnlyCookie());
        }
    }

}