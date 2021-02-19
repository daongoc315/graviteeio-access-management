/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.am.gateway.handler.common.vertx.web.auth.provider.impl;

import com.google.common.base.Strings;
import io.gravitee.am.common.jwt.Claims;
import io.gravitee.am.common.oauth2.Parameters;
import io.gravitee.am.gateway.handler.common.auth.user.NegotiateUserAuthentication;
import io.gravitee.am.gateway.handler.common.auth.user.UserAuthenticationManager;
import io.gravitee.am.gateway.handler.common.client.ClientSyncService;
import io.gravitee.am.gateway.handler.common.utils.ConstantKeys;
import io.gravitee.am.gateway.handler.common.vertx.core.http.VertxHttpServerRequest;
import io.gravitee.am.gateway.handler.common.vertx.web.auth.user.User;
import io.gravitee.am.identityprovider.api.Authentication;
import io.gravitee.am.identityprovider.api.SimpleAuthenticationContext;
import io.gravitee.am.model.oidc.Client;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.reactivex.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class SpengoAuthProviderImpl extends UserAuthProviderImpl {

    private final static Logger logger = LoggerFactory.getLogger(SpengoAuthProviderImpl.class);

    @Autowired
    private UserAuthenticationManager userAuthenticationManager;

    @Autowired
    private ClientSyncService clientSyncService;

    @Override
    public void authenticate(RoutingContext context, JsonObject authInfo, Handler<AsyncResult<User>> handler) {
        final String token = authInfo.getString(ConstantKeys.AUTH_NEGOTIATE_KEY);

        if (Strings.isNullOrEmpty(token)) {
            super.authenticate(context, authInfo, handler);
        } else {

            String clientId = authInfo.getString(Parameters.CLIENT_ID);
            String ipAddress = authInfo.getString(Claims.ip_address);
            String userAgent = authInfo.getString(Claims.user_agent);

            parseClient(clientId, parseClientHandler -> {
                if (parseClientHandler.failed()) {
                    logger.error("Authentication failure: unable to retrieve client " + clientId, parseClientHandler.cause());
                    handler.handle(Future.failedFuture(parseClientHandler.cause()));
                    return;
                }

                // retrieve the client (application)
                final Client client = parseClientHandler.result();

                // end user authentication
                SimpleAuthenticationContext authenticationContext = new SimpleAuthenticationContext(new VertxHttpServerRequest(context.request().getDelegate()));
                final Authentication authentication = new NegotiateUserAuthentication(token, authenticationContext);

                authenticationContext.set(Claims.ip_address, ipAddress);
                authenticationContext.set(Claims.user_agent, userAgent);
                authenticationContext.set(Claims.domain, client.getDomain());

                userAuthenticationManager.authenticate(client, authentication)
                        .subscribe(
                                user -> handler.handle(Future.succeededFuture(new User(user))),
                                error -> handler.handle(Future.failedFuture(error))
                        );
            });
        }
    }

}
