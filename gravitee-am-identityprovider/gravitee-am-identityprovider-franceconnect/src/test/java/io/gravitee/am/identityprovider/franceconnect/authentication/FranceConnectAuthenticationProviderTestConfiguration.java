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
package io.gravitee.am.identityprovider.franceconnect.authentication;

import io.gravitee.am.identityprovider.api.AuthenticationProvider;
import io.gravitee.am.identityprovider.api.DefaultIdentityProviderMapper;
import io.gravitee.am.identityprovider.api.DefaultIdentityProviderRoleMapper;
import io.gravitee.am.identityprovider.franceconnect.FranceConnectIdentityProviderConfiguration;
import io.gravitee.am.service.http.WebClientBuilder;
import io.vertx.reactivex.core.Vertx;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Properties;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Configuration
public class FranceConnectAuthenticationProviderTestConfiguration {

    @Bean
    public FranceConnectIdentityProviderConfiguration githubIdentityProviderConfiguration() {
        FranceConnectIdentityProviderConfiguration configuration = new FranceConnectIdentityProviderConfiguration();

        configuration.setClientId("test-client-id");
        configuration.setClientSecret("test-client-secret");
        configuration.setAccessTokenUri("http://localhost:19998/oauth/token");
        configuration.setUserAuthorizationUri("http://localhost:19998/oauth/authorize");
        configuration.setUserProfileUri("http://localhost:19998/profile");
        configuration.setEnvironment(FranceConnectIdentityProviderConfiguration.Environment.TEST);
        return configuration;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new FranceConnectAuthenticationProvider();
    }

    @Bean("graviteeProperties")
    public Properties properties() {
        return new Properties();
    }

    @Bean
    public Vertx vertx() {
        return Vertx.vertx();
    }

    @Bean
    public DefaultIdentityProviderRoleMapper roleMapper() {
        return new DefaultIdentityProviderRoleMapper();
    }

    @Bean
    public DefaultIdentityProviderMapper mapper() {
        return new DefaultIdentityProviderMapper();
    }

    @Bean
    public WebClientBuilder webClientBuilder() {
        return new WebClientBuilder();
    }
}