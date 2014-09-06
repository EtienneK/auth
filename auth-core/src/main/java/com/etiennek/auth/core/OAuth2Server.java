package com.etiennek.auth.core;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import com.etiennek.auth.core.model.ErrorCode;
import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.resp.ErrorResponse;
import com.google.common.collect.ImmutableMap;

public class OAuth2Server {

  private OAuth2ServerConfiguration configuration;

  public OAuth2Server(OAuth2ServerConfiguration configuration) {
    this.configuration = configuration;
  }

  public CompletableFuture<Response> grant(Request request) {
    Grant grant = new Grant(request);

    return CompletableFuture.<Void>completedFuture(null).thenComposeAsync(grant::extractCredentials)
        .thenComposeAsync(grant::generateAccessToken).thenComposeAsync(grant::generateRefreshToken)
        .thenComposeAsync(grant::sendResponse, configuration.getExecutor()).exceptionally((e) -> {
          Throwable cause = e.getCause();
          if (e instanceof CompletionException && cause instanceof OAuth2Exception)
            return new ErrorResponse(((OAuth2Exception) cause).getErrorCode(), e.getMessage());
          else
            return new ErrorResponse(ErrorCode.SERVER_ERROR, "An unknown error has occured.");
        });


    /*
     * extractCredentials, checkClient, checkGrantTypeAllowed, checkGrantType, generateAccessToken,
     * saveAccessToken, generateRefreshToken, saveRefreshToken, sendResponse
     */
  }

  private class Grant {
    private Request request;

    private String accessToken;
    private String refreshToken;

    public Grant(Request request) {
      this.request = request;
    }

    CompletableFuture<Void> extractCredentials(Void v) {
      CompletableFuture<Void> ret = new CompletableFuture<>();
      String contentType = request.getHeader().get("Content-Type");
      if (!request.getMethod().equals("POST") || contentType == null
          || !contentType.equals("application/x-www-form-urlencoded")) {
        ret.completeExceptionally(new OAuth2Exception(ErrorCode.INVALID_REQUEST,
            "Method must be POST with application/x-www-form-urlencoded encoding."));
        return ret;
      }

      ret.complete(null);
      return ret;
    }

    CompletableFuture<Void> generateAccessToken(Void v) {
      return configuration.getFuncs().getTokenGeneration().generateToken(TokenType.ACCESS).thenApplyAsync((result) -> {
        accessToken = result.token;
        return null;
      }, configuration.getExecutor());
    }

    CompletableFuture<Void> generateRefreshToken(Void v) {
      return configuration.getFuncs().getTokenGeneration().generateToken(TokenType.REFRESH)
          .thenApplyAsync((result) -> {
            refreshToken = result.token;
            return null;
          }, configuration.getExecutor());
    }

    CompletableFuture<Response> sendResponse(Void v) {
      ImmutableMap<String, String> header =
          ImmutableMap.of("Content-Type", "application/json;charset=UTF-8", "Cache-Control", "no-store", "Pragma",
              "no-cache");

      StringBuilder body = new StringBuilder();
      body.append("{").append("\n");
      body.append("\t\"access_token\":").append("\"").append(accessToken).append("\",").append("\n");
      body.append("\t\"token_type\":").append("\"").append("bearer").append("\",").append("\n");
      if (configuration.getAccessTokenLifetime().isPresent()) {
        body.append("\t\"expires_in\":").append("\"").append(configuration.getAccessTokenLifetime().get().getSeconds())
            .append("\",").append("\n");
      }
      if (configuration.getFuncs().getRefreshCode().isPresent()) {
        body.append("\t\"refresh_token\":").append("\"").append(refreshToken).append("\"").append("\n");
      }
      body.append("}");

      return CompletableFuture.completedFuture(new Response(200, header, body.toString()));
    }

  }

}
