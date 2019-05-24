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
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.TimeUnit;
import org.forgerock.util.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.UUID;

import static java.util.concurrent.TimeUnit.HOURS;

@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = SetCookie.Config.class)
public class SetCookie extends SingleOutcomeNode {

    private static final Duration EXPIRY_TIME_IN_HOURS = Duration.duration(5, HOURS);
    private static final String COOKIE_NAME = "Custom_Cookie";
    private static final String SESSION_PROPERTY = "Session_Value";

    private final Logger logger = LoggerFactory.getLogger(SetCookie.class);
    private final UUID nodeId;


    @Inject
    public SetCookie(@Assisted UUID nodeId) {
        this.nodeId = nodeId;
    }

    @Override
    public Action process(TreeContext treeContext) {
        logger.debug("SetCookie started");
        return goToNext()
                .addSessionHook(SetCookieTreeHook.class, nodeId, getClass().getSimpleName())
                .build();
    }


    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * The max life. The cookies become invalid after this amount of time.
         *
         * @return the max life in hours.
         */
        @Attribute(order = 100)
        default String cookieName() {
            return COOKIE_NAME;
        }

        /**
         * The max life. The cookies become invalid after this amount of time.
         *
         * @return the max life in hours.
         */
        @Attribute(order = 200)
        default String sessionProperty() {
            return SESSION_PROPERTY;
        }

        /**
         * The max life. The cookies become invalid after this amount of time.
         *
         * @return the max life in hours.
         */
        @Attribute(order = 300)
        @TimeUnit(HOURS)
        default Duration maxLife() {
            return EXPIRY_TIME_IN_HOURS;
        }

        /**
         * If true, instructs the browser to only send the cookie on secure connections.
         *
         * @return true to use secure cookie.
         */
        @Attribute(order = 400)
        default boolean useSecureCookie() {
            return true;
        }

        /**
         * If true, instructs the browser to prevent access to this cookie and only use it for http.
         *
         * @return true to use http only cookie.
         */
        @Attribute(order = 500)
        default boolean useHttpOnlyCookie() {
            return true;
        }
    }
}
