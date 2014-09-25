package com.etiennek.auth.core;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.etiennek.auth.core.model.ErrorCode.*;

import com.etiennek.auth.core.resp.ErrorResponse;

public class OAuth2Server {
  private static final Logger LOG = Logger.getLogger(Grant.class.getName());

  OAuth2ServerConfiguration config;

  public OAuth2Server(OAuth2ServerConfiguration configuration) {
    this.config = configuration;
  }

  public CompletableFuture<Response> grant(FormRequest request) {
    Grant grant = new Grant(config, request);
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
                  .exceptionally(this::generateErrorResponse);
    } catch (Exception e) {
      return CompletableFuture.completedFuture(generateErrorResponse(e));
    }
  }

  private ErrorResponse generateErrorResponse(Throwable e) {
    ErrorResponse ret;
    Throwable cause = e.getCause();
    if (e instanceof CompletionException && cause instanceof OAuth2Exception) {
      String message = cause.getMessage();
      ret = new ErrorResponse(((OAuth2Exception) cause).getErrorCode(), message);
    } else if (e instanceof OAuth2Exception) {
      String message = e.getMessage();
      ret = new ErrorResponse(((OAuth2Exception) e).getErrorCode(), message);
    } else {
      ret = new ErrorResponse(SERVER_ERROR, "An unknown error has occured.");
    }

    if (ret.getCode() >= 500) {
      LOG.log(Level.SEVERE, String.format("%s", ret), e);
    } else {
      LOG.log(Level.INFO, String.format("%s", ret));
    }

    return ret;
  }

}
