package com.etiennek.auth.core;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static com.etiennek.auth.core.Const.*;
import static com.etiennek.auth.core.Util.*;
import static com.etiennek.auth.core.model.ErrorCode.*;

import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.model.User;
import com.etiennek.auth.core.resp.AccessTokenResponse;
import com.etiennek.auth.core.resp.ErrorResponse;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

public class OAuth2Server {

  private OAuth2ServerConfiguration config;

  public OAuth2Server(OAuth2ServerConfiguration configuration) {
    this.config = configuration;
  }

  public CompletableFuture<Response> grant(Request request) {
    Grant grant = new Grant(request);
    try {
      return grant.extractCredentials(null)
                  .thenCompose(grant::checkClient)
                  .thenCompose(grant::checkGrantTypeAllowed)
                  .thenCompose(grant::checkGrantType)
                  .thenCompose(grant::generateAccessToken)
                  .thenCompose(grant::saveAccessToken)
                  .thenCompose(grant::generateRefreshToken)
                  .thenCompose(grant::saveRefreshToken)
                  .thenCompose(grant::sendResponse)
                  .exceptionally(grant::generateErrorResponse);
    } catch (Exception e) {
      return CompletableFuture.completedFuture(grant.generateErrorResponse(e));
    }
  }

  private class Grant {
    private ImmutableMap<String, ImmutableList<String>> body;

    private Request request;

    private String clientId;
    private String clientSecret;

    private String accessToken;
    private String refreshToken;
    private String grantType;

    private User user;

    public Grant(Request request) {
      this.request = request;
    }

    CompletableFuture<Void> extractCredentials(Void v) {
      CompletableFuture<Void> ret = new CompletableFuture<>();
      String contentType = request.getHeader()
                                  .get("Content-Type");

      // Only POST via application/x-www-form-urlencoded is acceptable
      if (!request.getMethod()
                  .equals(METHOD_POST) || contentType == null || !contentType.equals(MEDIA_X_WWW_FORM_URLENCODED)) {
        throw new OAuth2Exception(INVALID_REQUEST,
            "Method must be POST with application/x-www-form-urlencoded encoding.");
      }

      body = splitQuery(request.getBody());

      // Grant type
      grantType = body.containsKey(KEY_GRANT_TYPE) ? body.get(KEY_GRANT_TYPE)
                                                         .get(0)
                                                         .trim()
                                                         .toLowerCase() : null;
      if (!config.getSupportedGrantTypes()
                 .contains(grantType)) {
        throw new OAuth2Exception(INVALID_REQUEST, "Invalid or missing grant_type parameter.");
      }

      // Client Credentials
      Optional<ImmutableList<String>> ccHeader = getBasicAuthCredentialsHeader(request.getHeader()
                                                                                      .get("Authorization"));
      if (ccHeader.isPresent()) {
        ImmutableList<String> cc = ccHeader.get();
        clientId = cc.get(0);
        if (clientId == null || !clientId.matches(config.getRegex()
                                                        .getClientId()) || clientId.trim()
                                                                                   .isEmpty()) {
          throw new OAuth2Exception(INVALID_CLIENT, "Missing client_id parameter.");
        }
        clientSecret = cc.get(1);
        if (clientSecret == null || clientId.trim()
                                            .isEmpty()) {
          throw new OAuth2Exception(INVALID_CLIENT, "Missing client_secret parameter.");
        }
      } else {
        throw new OAuth2Exception(INVALID_CLIENT, "Invalid or missing client credentials.");
      }

      ret.complete(null);
      return ret;
    }

    CompletableFuture<Void> checkClient(Void v) {
      return config.getFuncs()
                   .getReq()
                   .getClient(clientId, clientSecret)
                   .thenAccept((result) -> {
                     Preconditions.checkNotNull(result);
                     if (!result.client.isPresent()) {
                       throw new OAuth2Exception(INVALID_CLIENT, "Invalid client credentials.");
                     }
                   });
    }

    CompletableFuture<Void> checkGrantTypeAllowed(Void v) {
      return config.getFuncs()
                   .getReq()
                   .isGrantTypeAllowed(clientId, grantType)
                   .thenAccept((result) -> {
                     Preconditions.checkNotNull(result);
                     if (result == null || !result.allowed) {
                       throw new OAuth2Exception(INVALID_CLIENT, "The grant type is unauthorised for this client_id.");
                     }
                   });
    }

    CompletableFuture<Void> checkGrantType(Void v) {
      switch (grantType) {
        case GRANT_PASSWORD:
          return usePasswordGrant();
      }
      throw new OAuth2Exception(INVALID_REQUEST, "Invalid grant_type parameter or parameter missing.");
    }

    CompletableFuture<Void> generateAccessToken(Void v) {
      return config.getFuncs()
                   .getTokenGeneration()
                   .generateToken(TokenType.ACCESS)
                   .thenAccept((result) -> {
                     Preconditions.checkNotNull(result);
                     Preconditions.checkNotNull(result.token);
                     accessToken = result.token;
                   });
    }

    CompletableFuture<Void> saveAccessToken(Void v) {
      Optional<LocalDateTime> expires;
      Optional<Duration> lifeTime = config.getAccessTokenLifetime();
      if (lifeTime.isPresent()) {
        expires = Optional.of(LocalDateTime.now()
                                           .plus(lifeTime.get()));
      } else {
        expires = Optional.empty();
      }
      return config.getFuncs()
                   .getReq()
                   .saveAccessToken(accessToken, clientId, user, expires);
    }

    CompletableFuture<Void> generateRefreshToken(Void v) {
      if (!config.getFuncs()
                 .getRefreshToken()
                 .isPresent()) {
        return CompletableFuture.completedFuture(null);
      }

      return config.getFuncs()
                   .getTokenGeneration()
                   .generateToken(TokenType.REFRESH)
                   .thenAccept((result) -> {
                     Preconditions.checkNotNull(result);
                     Preconditions.checkNotNull(result.token);
                     refreshToken = result.token;
                   });
    }

    CompletableFuture<Void> saveRefreshToken(Void v) {
      if (!config.getFuncs()
                 .getRefreshToken()
                 .isPresent()) {
        return CompletableFuture.completedFuture(null);
      }

      Optional<LocalDateTime> expires;
      Optional<Duration> lifeTime = config.getRefreshTokenLifetime();
      if (lifeTime.isPresent()) {
        expires = Optional.of(LocalDateTime.now()
                                           .plus(lifeTime.get()));
      } else {
        expires = Optional.empty();
      }
      return config.getFuncs()
                   .getRefreshToken()
                   .get()
                   .saveRefreshToken(refreshToken, clientId, user, expires);
    }

    CompletableFuture<Response> sendResponse(Void v) {
      return CompletableFuture.completedFuture(new AccessTokenResponse(accessToken, config.getAccessTokenLifetime(),
          refreshToken == null ? Optional.empty() : Optional.of(refreshToken)));
    }

    public ErrorResponse generateErrorResponse(Throwable e) {
      Throwable cause = e.getCause();
      if (e instanceof CompletionException && cause instanceof OAuth2Exception) {
        String message = cause.getMessage();
        return new ErrorResponse(((OAuth2Exception) cause).getErrorCode(), message);
      } else if (e instanceof OAuth2Exception) {
        String message = e.getMessage();
        return new ErrorResponse(((OAuth2Exception) e).getErrorCode(), message);
      }
      // TODO: Logging
      return new ErrorResponse(SERVER_ERROR, "An unknown error has occured.");
    }

    // Grants

    private CompletableFuture<Void> usePasswordGrant() {
      if (!body.containsKey("username") || !body.containsKey("password")) {
        throw new OAuth2Exception(INVALID_CLIENT, "Missing parameters. 'username' and 'password' are required.");
      }
      String username = body.get("username")
                            .get(0);
      String password = body.get("password")
                            .get(0);
      return config.getFuncs()
                   .getPassword()
                   .get()
                   .getUser(username, password)
                   .thenAccept((result) -> {
                     Preconditions.checkNotNull(result);
                     if (result.user.isPresent()) {
                       user = result.user.get();
                     } else {
                       throw new OAuth2Exception(INVALID_GRANT, "User credentials are invalid.");
                     }
                   });
    }
  }

}
