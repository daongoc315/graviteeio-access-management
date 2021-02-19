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

import io.gravitee.am.common.exception.authentication.NegotiateContinueException;
import io.gravitee.am.common.jwt.Claims;
import io.gravitee.am.common.oauth2.Parameters;
import io.gravitee.am.gateway.handler.common.utils.ConstantKeys;
import io.gravitee.am.gateway.handler.common.vertx.utils.RequestUtils;
import io.gravitee.am.gateway.handler.common.vertx.utils.UriBuilderRequest;
import io.gravitee.am.gateway.handler.common.vertx.web.auth.provider.UserAuthProvider;
import io.gravitee.am.gateway.handler.common.vertx.web.auth.user.User;
import io.gravitee.common.http.HttpHeaders;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.reactivex.core.MultiMap;
import io.vertx.reactivex.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.gravitee.am.gateway.handler.common.utils.ConstantKeys.*;
import static io.gravitee.am.gateway.handler.common.vertx.utils.UriBuilderRequest.CONTEXT_PATH;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class LoginNegotiateAuthenticationHandler implements Handler<RoutingContext> {
    private static final Logger LOGGER = LoggerFactory.getLogger(LoginNegotiateAuthenticationHandler.class);

    private final UserAuthProvider authProvider;
    private final Handler<RoutingContext> flowHandler;

    public LoginNegotiateAuthenticationHandler(UserAuthProvider authProvider, Handler<RoutingContext> postLoginFlow) {
        this.authProvider = authProvider;
        this.flowHandler = postLoginFlow;
    }

    @Override
    public void handle(RoutingContext context) {
        String authHeader = context.request().getHeader(io.vertx.core.http.HttpHeaders.AUTHORIZATION);
        boolean hasNegotiateToken = (authHeader != null && authHeader.trim().startsWith(AUTH_NEGOTIATE_KEY));
        if (hasNegotiateToken) {
            MultiMap params = context.request().params();
            String clientId = params.get(Parameters.CLIENT_ID);
            if (clientId == null) {
                LOGGER.warn("No client id - did you forget to include client_id query parameter ?");
                context.fail(400);
                return;
            }

            JsonObject authInfo = new JsonObject()
                    .put(AUTH_NEGOTIATE_KEY, authHeader.replaceFirst(AUTH_NEGOTIATE_KEY, "").trim())
                    .put(Claims.ip_address, RequestUtils.remoteAddress(context.request()))
                    .put(Claims.user_agent, RequestUtils.userAgent(context.request()))
                    .put(Parameters.CLIENT_ID, clientId);

            authProvider.authenticate(context, authInfo, res -> {
                if (res.failed()) {
                    LOGGER.debug("SPNEGO token is invalid, continue flow to display login form");
                    if (res.cause() instanceof NegotiateContinueException) {
                        // mutual authentication is requested by client,
                        // update the context with the challenge token
                        context.put(ASK_FOR_NEGOTIATE_KEY, true);
                        context.put(NEGOTIATE_CONTINUE_TOKEN_KEY, ((NegotiateContinueException) res.cause()).getToken());
                    }
                    context.next();
                    return;
                }

                // authentication success
                // set user into the context and continue
                final User result = res.result();
                context.getDelegate().setUser(result);
                context.put(ConstantKeys.USER_CONTEXT_KEY, result.getUser());

                if (this.flowHandler != null) {
                    // execute POST_LOGIN flow
                    this.flowHandler.handle(context);
                }

                if (!context.failed()) {
                    // If the context doesn't fail due to POST_LOGIN processing
                    // redirect the user to configured URI
                    doRedirect(context);
                }
                return;

            });
        } else {
            LOGGER.debug("SPNEGO token is missing, continue flow to display login form");
            context.next();
        }
    }

    private void doRedirect(RoutingContext context) {
        // the login process is done thanks to the SPNEGO token
        // redirect the user to the original request
        final MultiMap queryParams = RequestUtils.getCleanedQueryParams(context.request());
        final String redirectUri = UriBuilderRequest.resolveProxyRequest(context.request(), context.get(CONTEXT_PATH) + "/oauth/authorize", queryParams);
        context.response().putHeader(HttpHeaders.LOCATION, redirectUri)
                .setStatusCode(302)
                .end();
    }
}
