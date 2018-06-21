/*
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
 * Copyright 2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.RequiredValueValidator;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.nodes.treehook.CreateCustomPersistentCookieTreeHook;
import org.forgerock.openam.auth.nodes.validators.HmacSigningKeyValidator;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.sm.annotations.adapters.TimeUnit;
import org.forgerock.util.time.Duration;

import javax.inject.Inject;
import java.util.Set;
import java.util.UUID;

import static java.util.concurrent.TimeUnit.HOURS;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;


/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = SetCustomPersistentCookie.Config.class)
public class SetCustomPersistentCookie extends SingleOutcomeNode {

    private final static String DEBUG_FILE = "SetCustomPersistentCookie";
    private static final String BUNDLE = SetCustomPersistentCookie.class.getName().replace(".", "/");
    private static final Duration JWT_IDLE_TIMEOUT_IN_HOURS = Duration.duration(5, HOURS);
    private static final Duration JWT_EXPIRY_TIME_IN_HOURS = Duration.duration(5, HOURS);
    private static final String DEFAULT_COOKIE_NAME = "session-jwt";
    private final Config config;
    private final UUID nodeId;
    private final CoreWrapper coreWrapper;
    private Debug debug = Debug.getInstance(DEBUG_FILE);

    private String SESSION_USERNAME = "SESSION_USERNAME";
    private String SESSION_REALM_NAME = "SESSION_REALM_NAME";


    /**
     * A {@link SetCustomPersistentCookie} constructor.
     *
     * @param config The service config.
     * @param nodeId the uuid of this node instance.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public SetCustomPersistentCookie(@Assisted Config config, @Assisted UUID nodeId, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.nodeId = nodeId;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        debug.message("SetCustomPersistentCookieNode started");
        debug.message("Custom persistent cookie set");

        return goToNext()
//                   .putSessionProperty(PERSISTENT_COOKIE_SESSION_PROPERTY, config.persistentCookieName())
                .putSessionProperty(SESSION_USERNAME, context.sharedState.get(USERNAME).asString())
                .putSessionProperty(SESSION_REALM_NAME, context.sharedState.get(REALM).asString())
                .addSessionHook(CreateCustomPersistentCookieTreeHook.class, nodeId, getClass().getSimpleName())
                .build();
    }


    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * The max life. The cookie becomes invalid after this amount of time.
         *
         * @return the max life in hours.
         */
        @Attribute(order = 200)
        @TimeUnit(HOURS)
        default Duration maxLife() {
            return JWT_EXPIRY_TIME_IN_HOURS;
        }

        /**
         * If true, instructs the browser to only send the cookie on secure connections.
         *
         * @return true to use secure cookie.
         */
        @Attribute(order = 300)
        default boolean useSecureCookie() {
            return true;
        }

        /**
         * If true, instructs the browser to prevent access to this cookie and only use it for http.
         *
         * @return true to use http only cookie.
         */
        @Attribute(order = 400)
        default boolean useHttpOnlyCookie() {
            return true;
        }

        /**
         * The signing key.
         *
         * @return the hmac signing key.
         */
        @Attribute(order = 500, validators = {RequiredValueValidator.class, HmacSigningKeyValidator.class})
        @Password
        char[] hmacSigningKey();

        /**
         * The name of the persistent cookie.
         *
         * @return the name of the persistent cookie.
         */
        @Attribute(order = 600)
        default String persistentCookieName() {
            return DEFAULT_COOKIE_NAME;
        }

        /**
         * Primary LDAP server configuration.
         *
         * @return the set
         */
        @Attribute(order = 700, validators = {RequiredValueValidator.class})
        Set<String> userAttributes();

    }
}