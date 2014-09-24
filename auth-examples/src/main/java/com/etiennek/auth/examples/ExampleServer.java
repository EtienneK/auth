package com.etiennek.auth.examples;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.OAuth2Server;
import com.etiennek.auth.core.OAuth2ServerConfiguration;
import com.etiennek.auth.core.model.AccessToken;
import com.etiennek.auth.core.model.Client;
import com.etiennek.auth.core.model.RequiredFunctions;
import com.etiennek.auth.core.model.User;
import com.etiennek.auth.core.model.RequiredFunctions.PasswordGrantType;

public class ExampleServer extends OAuth2Server {

  public ExampleServer() {
    super(configuration());
  }

  private static OAuth2ServerConfiguration configuration() {

    List<AccessToken> accessTokens = new ArrayList<>();
    List<Client> clients = new ArrayList<>();
    clients.add(new Client("client1", "secret1"));
    clients.add(new Client("client2", "secret2"));

    List<User> users = new ArrayList<>();
    users.add(new User("1", "user1", "password1"));
    users.add(new User("2", "user2", "password2"));

    return new OAuth2ServerConfiguration.Builder(new RequiredFunctions() {
      @Override
      public CompletableFuture<GetAccessTokenRes> getAccessToken(String bearerToken) {
        // TODO: Maybe move getAccessToken to the non required functions
        throw new UnsupportedOperationException();
      }

      @Override
      public CompletableFuture<GetClientRes> getClient(String clientId, String clientSecret) {
        Optional<Client> client = clients.stream()
                                         .filter((c) -> {
                                           return c.getId()
                                                   .equals(clientId) && c.getSecret()
                                                                         .equals(clientSecret);
                                         })
                                         .findFirst();
        return CompletableFuture.completedFuture(new GetClientRes(client));
      }

      @Override
      public CompletableFuture<IsGrantTypeAllowedRes> isGrantTypeAllowed(String clientId, String grantType) {
        return CompletableFuture.completedFuture(new IsGrantTypeAllowedRes(true));
      }

      @Override
      public CompletableFuture<Void> saveAccessToken(String accessToken, String clientId, String userId,
          Optional<LocalDateTime> expires) {
        accessTokens.add(new AccessToken(accessToken, clientId, userId, expires.isPresent() ? expires.get() : null));
        return CompletableFuture.completedFuture(null);
      }

    }).withPasswordGrantTypeSupport(new PasswordGrantType() {

      @Override
      public CompletableFuture<GetUserRes> getUser(String username, String password) {
        Optional<User> user = users.stream()
                                   .filter((u) -> {
                                     return u.getId()
                                             .equals(username) && u.getPassword()
                                                                   .equals(password);
                                   })
                                   .findFirst();
        return CompletableFuture.completedFuture(new GetUserRes(user));
      }

    })
      .build();
  }
}
