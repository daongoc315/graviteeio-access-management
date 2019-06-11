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
package io.gravitee.am.management.service;

import io.gravitee.am.identityprovider.api.UserProvider;
import io.gravitee.am.management.service.impl.UserServiceImpl;
import io.gravitee.am.model.Client;
import io.gravitee.am.model.User;
import io.gravitee.am.service.AuditService;
import io.gravitee.am.service.ClientService;
import io.gravitee.am.service.exception.ClientNotFoundException;
import io.gravitee.am.service.exception.UserProviderNotFoundException;
import io.gravitee.am.service.model.NewUser;
import io.gravitee.am.service.model.UpdateUser;
import io.reactivex.Maybe;
import io.reactivex.observers.TestObserver;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class UserServiceTest {

    @InjectMocks
    private UserService userService = new UserServiceImpl();

    @Mock
    private IdentityProviderManager identityProviderManager;

    @Mock
    private AuditService auditService;

    @Mock
    private ClientService clientService;

    @Mock
    private io.gravitee.am.service.UserService commonUserService;

    @Test
    public void shouldCreateUser_invalid_identity_provider() {
        final String domain = "domain";

        NewUser newUser = mock(NewUser.class);
        when(newUser.getSource()).thenReturn("unknown-idp");

        when(identityProviderManager.getUserProvider(anyString())).thenReturn(Maybe.empty());

        TestObserver<User> testObserver = userService.create(domain, newUser).test();
        testObserver.assertNotComplete();
        testObserver.assertError(UserProviderNotFoundException.class);
    }

    @Test
    public void shouldNotCreateUser_unknown_client() {
        final String domain = "domain";

        NewUser newUser = mock(NewUser.class);
        when(newUser.getSource()).thenReturn("idp");
        when(newUser.getClient()).thenReturn("client");

        UserProvider userProvider = mock(UserProvider.class);

        when(identityProviderManager.getUserProvider(anyString())).thenReturn(Maybe.just(userProvider));
        when(clientService.findById(newUser.getClient())).thenReturn(Maybe.empty());
        when(clientService.findByDomainAndClientId(domain, newUser.getClient())).thenReturn(Maybe.empty());

        TestObserver<User> testObserver = userService.create(domain, newUser).test();
        testObserver.assertNotComplete();
        testObserver.assertError(ClientNotFoundException.class);
    }

    @Test
    public void shouldNotCreateUser_invalid_client() {
        final String domain = "domain";

        NewUser newUser = mock(NewUser.class);
        when(newUser.getSource()).thenReturn("idp");
        when(newUser.getClient()).thenReturn("client");

        UserProvider userProvider = mock(UserProvider.class);

        Client client = mock(Client.class);
        when(client.getDomain()).thenReturn("other-domain");

        when(identityProviderManager.getUserProvider(anyString())).thenReturn(Maybe.just(userProvider));
        when(clientService.findById(newUser.getClient())).thenReturn(Maybe.just(client));

        TestObserver<User> testObserver = userService.create(domain, newUser).test();
        testObserver.assertNotComplete();
        testObserver.assertError(ClientNotFoundException.class);
    }

    @Test
    public void shouldNotUpdateUser_unknown_client() {
        final String domain = "domain";
        final String id = "id";

        User user = mock(User.class);
        when(user.getSource()).thenReturn("idp");

        UpdateUser updateUser = mock(UpdateUser.class);
        when(updateUser.getClient()).thenReturn("client");

        UserProvider userProvider = mock(UserProvider.class);

        when(commonUserService.findById(id)).thenReturn(Maybe.just(user));
        when(identityProviderManager.getUserProvider(anyString())).thenReturn(Maybe.just(userProvider));
        when(clientService.findById(updateUser.getClient())).thenReturn(Maybe.empty());
        when(clientService.findByDomainAndClientId(domain, updateUser.getClient())).thenReturn(Maybe.empty());

        TestObserver<User> testObserver = userService.update(domain, id, updateUser).test();
        testObserver.assertNotComplete();
        testObserver.assertError(ClientNotFoundException.class);
    }

    @Test
    public void shouldNotUpdateUser_invalid_client() {
        final String domain = "domain";
        final String id = "id";

        User user = mock(User.class);
        when(user.getSource()).thenReturn("idp");

        UpdateUser updateUser = mock(UpdateUser.class);
        when(updateUser.getClient()).thenReturn("client");

        UserProvider userProvider = mock(UserProvider.class);

        Client client = mock(Client.class);
        when(client.getDomain()).thenReturn("other-domain");

        when(commonUserService.findById(id)).thenReturn(Maybe.just(user));
        when(identityProviderManager.getUserProvider(anyString())).thenReturn(Maybe.just(userProvider));
        when(clientService.findById(updateUser.getClient())).thenReturn(Maybe.just(client));

        TestObserver<User> testObserver = userService.update(domain, id, updateUser).test();
        testObserver.assertNotComplete();
        testObserver.assertError(ClientNotFoundException.class);
    }

}