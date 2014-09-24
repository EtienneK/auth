package com.etiennek.auth.core;

import static com.etiennek.auth.core.Const.GRANT_CLIENT_CREDENTIALS;
import static com.etiennek.auth.core.Const.GRANT_PASSWORD;
import static com.etiennek.auth.core.Const.GRANT_REFRESH_TOKEN;
import static com.etiennek.auth.core.Const.KEY_GRANT_TYPE;
import static com.etiennek.auth.core.Const.MEDIA_X_WWW_FORM_URLENCODED;
import static com.etiennek.auth.core.Const.METHOD_POST;
import static com.etiennek.auth.core.Util.getBasicAuthCredentialsHeader;
import static com.etiennek.auth.core.Util.splitQuery;
import static com.etiennek.auth.core.model.ErrorCode.INVALID_CLIENT;
import static com.etiennek.auth.core.model.ErrorCode.INVALID_GRANT;
import static com.etiennek.auth.core.model.ErrorCode.INVALID_REQUEST;
import static com.google.common.base.Preconditions.checkNotNull;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.RefreshToken;
import com.etiennek.auth.core.model.RequiredFunctions;
import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.model.RequiredFunctions.RefreshTokenGrantType;
import com.etiennek.auth.core.resp.AccessTokenResponse;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

class Grant {
  private OAuth2ServerConfiguration config;

  private ImmutableMap<String, ImmutableList<String>> body;

  private RequiredFunctions requiredFuncs;

  private Request request;

  private String clientId;
  private String clientSecret;

  private String accessToken;
  private String refreshToken;
  private String grantType;

  private String userId;

  public Grant(OAuth2ServerConfiguration config, Request request) {
    this.config = config;
    this.request = request;
    this.requiredFuncs = config.getFuncs()
                               .getRequired();
  }

  CompletableFuture<Void> extractCredentials(Void v) {
    CompletableFuture<Void> ret = new CompletableFuture<>();
    String contentType = request.getHeader()
                                .get("Content-Type");

    // Only POST via application/x-www-form-urlencoded is acceptable
    if (!request.getMethod()
                .equals(METHOD_POST) || contentType == null || !contentType.equals(MEDIA_X_WWW_FORM_URLENCODED)) {
      throw new OAuth2Exception(INVALID_REQUEST, "Method must be POST with application/x-www-form-urlencoded encoding.");
    }

    try {
      body = splitQuery(request.getBody());
    } catch (RuntimeException e) {
      throw new OAuth2Exception(INVALID_REQUEST, "Invalid request body.");
    }

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
    return requiredFuncs.getClient(clientId, clientSecret)
                        .thenAccept((result) -> {
                          checkNotNull(result);
                          if (!result.client.isPresent()) {
                            throw new OAuth2Exception(INVALID_CLIENT, "Invalid client credentials.");
                          }
                        });
  }

  CompletableFuture<Void> checkGrantTypeAllowed(Void v) {
    return requiredFuncs.isGrantTypeAllowed(clientId, grantType)
                        .thenAccept(
                            (result) -> {
                              checkNotNull(result);
                              if (result == null || !result.allowed) {
                                throw new OAuth2Exception(INVALID_CLIENT,
                                    "The grant type is unauthorised for this client_id.");
                              }
                            });
  }

  CompletableFuture<Void> checkGrantType(Void v) {
    switch (grantType) {
      case GRANT_PASSWORD:
        return usePasswordGrant();
      case GRANT_CLIENT_CREDENTIALS:
        return useClientCredentialsGrant();
      case GRANT_REFRESH_TOKEN:
        return useRefreshTokenGrant();
    }
    throw new OAuth2Exception(INVALID_REQUEST, "Invalid grant_type parameter or parameter missing.");
  }

  CompletableFuture<Void> generateAccessToken(Void v) {
    return requiredFuncs.generateToken(TokenType.ACCESS)
                        .thenAccept((result) -> {
                          checkNotNull(result);
                          checkNotNull(result.token);
                          accessToken = result.token;
                        });
  }

  CompletableFuture<Void> saveAccessToken(Void v) {
    Optional<LocalDateTime> expires;
    Optional<Duration> lifeTime = config.getAccessTokenLifetime();
    if (lifeTime.isPresent()) {
      expires = Optional.of(requiredFuncs.getNow()
                                         .plus(lifeTime.get()));
    } else {
      expires = Optional.empty();
    }
    return requiredFuncs.saveAccessToken(accessToken, clientId, userId, expires);
  }

  CompletableFuture<Void> generateRefreshToken(Void v) {
    if (!config.getFuncs()
               .getRefreshToken()
               .isPresent()) {
      return CompletableFuture.completedFuture(null);
    }

    return requiredFuncs.generateToken(TokenType.REFRESH)
                        .thenAccept((result) -> {
                          checkNotNull(result);
                          checkNotNull(result.token);
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
      expires = Optional.of(requiredFuncs.getNow()
                                         .plus(lifeTime.get()));
    } else {
      expires = Optional.empty();
    }
    return config.getFuncs()
                 .getRefreshToken()
                 .get()
                 .saveRefreshToken(refreshToken, clientId, userId, expires);
  }

  CompletableFuture<Response> sendResponse(Void v) {
    return CompletableFuture.completedFuture(new AccessTokenResponse(accessToken, config.getAccessTokenLifetime(),
        refreshToken == null ? Optional.empty() : Optional.of(refreshToken)));
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
                   checkNotNull(result);
                   if (result.user.isPresent()) {
                     userId = result.user.get()
                                         .getId();
                   } else {
                     throw new OAuth2Exception(INVALID_GRANT, "User credentials are invalid.");
                   }
                 });
  }

  private CompletableFuture<Void> useClientCredentialsGrant() {
    return config.getFuncs()
                 .getClientCreds()
                 .get()
                 .getUserFromClient(clientId, clientSecret)
                 .thenAccept((result) -> {
                   checkNotNull(result);
                   if (result.user.isPresent()) {
                     userId = result.user.get()
                                         .getId();
                   } else {
                     throw new OAuth2Exception(INVALID_GRANT, "Client credentials are invalid.");
                   }
                 });
  }

  private CompletableFuture<Void> useRefreshTokenGrant() {
    if (!body.containsKey("refresh_token")) {
      throw new OAuth2Exception(INVALID_REQUEST, "No 'refresh_token' parameter.");
    }
    String token = body.get("refresh_token")
                       .get(0);

    RefreshTokenGrantType funcs = config.getFuncs()
                                        .getRefreshToken()
                                        .get();

    return funcs.getRefreshToken(token)
                .thenCompose((result) -> {
                  checkNotNull(result);
                  if (!result.refreshToken.isPresent() || !clientId.equals(result.refreshToken.get()
                                                                                              .getClientId())) {
                    throw new OAuth2Exception(INVALID_GRANT, "Invalid refresh token.");
                  }

                  RefreshToken refreshToken = result.refreshToken.get();
                  if (refreshToken.hasExpired(requiredFuncs.getNow())) {
                    return funcs.revokeRefreshToken(token)
                                .thenAccept((v) -> {
                                  throw new OAuth2Exception(INVALID_GRANT, "Refresh token has expired.");
                                });
                  }

                  userId = checkNotNull(refreshToken.getUserId());
                  return funcs.revokeRefreshToken(token);
                });
  }
}
