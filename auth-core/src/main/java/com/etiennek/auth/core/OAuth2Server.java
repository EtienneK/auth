package com.etiennek.auth.core;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import static com.etiennek.auth.core.Const.*;
import static com.etiennek.auth.core.Util.*;
import static com.etiennek.auth.core.model.ErrorCode.*;

import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.resp.AccessTokenResponse;
import com.etiennek.auth.core.resp.GrantErrorResponse;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

public class OAuth2Server {

  private OAuth2ServerConfiguration configuration;

  public OAuth2Server(OAuth2ServerConfiguration configuration) {
    this.configuration = configuration;
  }

  public CompletableFuture<Response> grant(Request request) {
    Grant grant = new Grant(request);
    try {
      return grant.extractCredentials(null)
                  .thenCompose(grant::checkClient)
                  .thenCompose(grant::generateAccessToken)
                  .thenCompose(grant::generateRefreshToken)
                  .thenCompose(grant::sendResponse)
                  .exceptionally(grant::generateErrorResponse);
    } catch (Exception e) {
      return CompletableFuture.completedFuture(grant.generateErrorResponse(e));
    }

    /*
     * extractCredentials, checkClient, checkGrantTypeAllowed, checkGrantType, generateAccessToken,
     * saveAccessToken, generateRefreshToken, saveRefreshToken, sendResponse
     */
  }

  private class Grant {
    private ImmutableMap<String, ImmutableList<String>> body;

    private Request request;

    private String clientId;
    private String clientSecret;

    private String accessToken;
    private String refreshToken;
    private String grantType;

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
                                                         .get(0) : null;
      if (!configuration.getSupportedGrantTypes()
                        .contains(grantType)) {
        throw new OAuth2Exception(INVALID_REQUEST, "Invalid or missing grant_type parameter.");
      }

      // Client Credentials
      Optional<ImmutableList<String>> ccHeader = getBasicAuthCredentialsHeader(request.getHeader()
                                                                                      .get("Authorization"));
      if (ccHeader.isPresent()) {
        ImmutableList<String> cc = ccHeader.get();
        clientId = cc.get(0);
        if (clientId == null || !clientId.matches(configuration.getRegex()
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
      return configuration.getFuncs()
                          .getReq()
                          .getClient(clientId, clientSecret)
                          .thenAccept((result) -> {
                            if (result == null || !result.client.isPresent()) {
                              throw new OAuth2Exception(INVALID_CLIENT, "Invalid client credentials.");
                            }
                          });
    }

    CompletableFuture<Void> generateAccessToken(Void v) {
      return configuration.getFuncs()
                          .getTokenGeneration()
                          .generateToken(TokenType.ACCESS)
                          .thenAccept((result) -> {
                            accessToken = result.token;
                          });
    }

    CompletableFuture<Void> generateRefreshToken(Void v) {
      if (!configuration.getFuncs()
                        .getRefreshToken()
                        .isPresent()) {
        return CompletableFuture.completedFuture(null);
      }

      return configuration.getFuncs()
                          .getTokenGeneration()
                          .generateToken(TokenType.REFRESH)
                          .thenAccept((result) -> {
                            refreshToken = result.token;
                          });
    }

    CompletableFuture<Response> sendResponse(Void v) {
      return CompletableFuture.completedFuture(new AccessTokenResponse(accessToken,
          configuration.getAccessTokenLifetime(), refreshToken == null ? Optional.empty() : Optional.of(refreshToken)));
    }

    public GrantErrorResponse generateErrorResponse(Throwable e) {
      Throwable cause = e.getCause();
      if (e instanceof CompletionException && cause instanceof OAuth2Exception) {
        String message = cause.getMessage();
        return new GrantErrorResponse(((OAuth2Exception) cause).getErrorCode(), message);
      } else if (e instanceof OAuth2Exception) {
        String message = e.getMessage();
        return new GrantErrorResponse(((OAuth2Exception) e).getErrorCode(), message);
      } else {
        // TODO: Logging
        return new GrantErrorResponse(SERVER_ERROR, "An unknown error has occured.");
      }
    }
  }

}
