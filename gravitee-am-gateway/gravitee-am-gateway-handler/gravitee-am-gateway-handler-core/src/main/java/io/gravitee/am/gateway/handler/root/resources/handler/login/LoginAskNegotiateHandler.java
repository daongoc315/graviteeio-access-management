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
package io.gravitee.am.gateway.handler.root.resources.handler.login;

import io.gravitee.am.common.exception.oauth2.InvalidRequestException;
import io.gravitee.am.gateway.handler.common.auth.idp.IdentityProviderManager;
import io.gravitee.am.model.IdentityProvider;
import io.gravitee.am.model.oidc.Client;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.reactivex.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static io.gravitee.am.gateway.handler.common.utils.ConstantKeys.*;

/**
 * @author Eric LELEU (eric.leleu at graviteesource.com)
 * @author GraviteeSource Team
 */
public class LoginAskNegotiateHandler  implements Handler<RoutingContext> {
    private static final Logger LOGGER = LoggerFactory.getLogger(LoginAskNegotiateHandler.class);

    public static final String KERBEROS_AM_IDP = "kerberos-am-idp";

    private final IdentityProviderManager identityProviderManager;

    public LoginAskNegotiateHandler(IdentityProviderManager identityProviderManager) {
        this.identityProviderManager = identityProviderManager;
    }

    @Override
    public void handle(RoutingContext routingContext) {
        final Client client = routingContext.get(CLIENT_CONTEXT_KEY);
        // fetch client identity providers
        getSpnegoProviders(client.getIdentities(), identityProvidersResultHandler -> {
            if (identityProvidersResultHandler.failed()) {
                LOGGER.error("Unable to fetch client social identity providers", identityProvidersResultHandler.cause());
                routingContext.fail(new InvalidRequestException("Unable to fetch client social identity providers"));
            }

            List<IdentityProvider> spnegoProviders = identityProvidersResultHandler.result();
            // flag the context to ask negotiate for authentication if one of following condition match:
            // * at least one IdentityProvider manages this mechanism and the request doesn't contains an Authorization header with token
            // * the current request already received SPNEGO token but negotiation need to continue
            String authHeader = routingContext.request().getHeader(HttpHeaders.AUTHORIZATION);
            boolean withoutNegotiateToken = !(authHeader != null && authHeader.trim().startsWith(AUTH_NEGOTIATE_KEY));
            boolean supportNegotiate = !(spnegoProviders == null || spnegoProviders.isEmpty());
            boolean negotiateContinue = routingContext.get(ASK_FOR_NEGOTIATE_KEY) != null ? routingContext.get(ASK_FOR_NEGOTIATE_KEY) : false;
            routingContext.put(ASK_FOR_NEGOTIATE_KEY, negotiateContinue || (withoutNegotiateToken && supportNegotiate));

            routingContext.next();
            return;
        });

    }

    private void getSpnegoProviders(Set<String> identities, Handler<AsyncResult<List<IdentityProvider>>> resultHandler) {
        if (identities == null) {
            resultHandler.handle(Future.succeededFuture(Collections.emptyList()));
        } else {
            resultHandler.handle(Future.succeededFuture(identities.stream()
                    .map(identityProviderManager::getIdentityProvider)
                    .filter(identityProvider -> identityProvider != null && KERBEROS_AM_IDP.equals(identityProvider.getType()))
                    .collect(Collectors.toList())));
        }
    }

}
