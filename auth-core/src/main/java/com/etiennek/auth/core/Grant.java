package com.etiennek.auth.core;

import static com.etiennek.auth.core.Const.*;
import static com.etiennek.auth.core.model.ErrorCode.*;
import static com.etiennek.auth.core.Util.*;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.AuthCode;
import com.etiennek.auth.core.model.RefreshToken;
import com.etiennek.auth.core.model.RequiredFunctions;
import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.model.RequiredFunctions.RefreshTokenGrantType;
import com.etiennek.auth.core.resp.AccessTokenResponse;

class Grant {
  private OAuth2ServerConfiguration config;

  private Map<String, String[]> body;

  private RequiredFunctions requiredFuncs;

  private FormRequest request;

  private String clientId;
  private String clientSecret;

  private String accessToken;
  private String refreshToken;
  private String grantType;

  private String userId;

  Grant(OAuth2ServerConfiguration config, FormRequest request) {
    this.config = config;
    this.request = request;
    this.requiredFuncs = config.getFuncs()
                               .getRequired();
  }

  CompletableFuture<Void> extractCredentials(Void v) {
    CompletableFuture<Void> ret = new CompletableFuture<>();
    String[] contentTypeArr = request.getHeader()
                                     .get("Content-Type");

    // Only POST via application/x-www-form-urlencoded is acceptable
    if (!request.getMethod()
                .equalsIgnoreCase(METHOD_POST) || isNullOrEmpty(contentTypeArr)
        || !contentTypeArr[0].equals(MEDIA_X_WWW_FORM_URLENCODED)) {
      throw new OAuth2Exception(INVALID_REQUEST, "Method must be POST with application/x-www-form-urlencoded encoding.");
    }

    body = request.getBody();

    // Grant type
    grantType = !isNullOrEmpty(body.get(KEY_GRANT_TYPE)) ? body.get(KEY_GRANT_TYPE)[0].trim()
                                                                                      .toLowerCase() : null;
    if (!config.isSupportedGrantType(grantType)) {
      throw new OAuth2Exception(INVALID_REQUEST, "Invalid or missing grant_type parameter.");
    }

    // Client Credentials
    Optional<String[]> ccHeader = getBasicAuthCredentialsHeader(request.getHeader()
                                                                       .get("Authorization"));
    if (ccHeader.isPresent()) {
      String[] cc = ccHeader.get();
      clientId = cc[0];
      if (clientId == null || !clientId.matches(config.getRegex()
                                                      .getClientId()) || clientId.trim()
                                                                                 .isEmpty()) {
        throw new OAuth2Exception(INVALID_CLIENT, "Missing client_id parameter.");
      }
      clientSecret = cc[1];
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
      case GRANT_AUTHORIZATION_CODE:
        return useAuthCodeGrant();
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
    String username = isNullOrEmpty(body.get("username")) ? null : body.get("username")[0];
    String password = isNullOrEmpty(body.get("password")) ? null : body.get("password")[0];

    if (username == null || password == null) {
      throw new OAuth2Exception(INVALID_CLIENT, "Ivalid values for 'username' or 'password'.");
    }

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

  private CompletableFuture<Void> useAuthCodeGrant() {
    String code = isNullOrEmpty(body.get("code")) ? null : body.get("code")[0];
    if (code == null) {
      throw new OAuth2Exception(INVALID_REQUEST, "Ivalid or missing value for 'code'.");
    }

    return config.getFuncs()
                 .getAuthCode()
                 .get()
                 .getAuthCode(code)
                 .thenAccept((result) -> {
                   checkNotNull(result);
                   if (!result.authCode.isPresent() || !clientId.equals(result.authCode.get()
                                                                                       .getClientId())) {
                     throw new OAuth2Exception(INVALID_GRANT, "Invalid authorization code.");
                   }

                   AuthCode authCode = result.authCode.get();
                   if (authCode.hasExpired(requiredFuncs.getNow())) {
                     throw new OAuth2Exception(INVALID_GRANT, "Authorization code  has expired.");
                   }

                   userId = checkNotNull(authCode.getUserId());
                 });
  }

  private CompletableFuture<Void> useRefreshTokenGrant() {
    String token = isNullOrEmpty(body.get("refresh_token")) ? null : body.get("refresh_token")[0];
    if (token == null) {
      throw new OAuth2Exception(INVALID_REQUEST, "Ivalid or missing value for 'refresh_token'.");
    }

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
