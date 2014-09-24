package com.etiennek.auth.core.model.func;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.AccessToken;

@FunctionalInterface
public interface GetAccessToken {
  CompletableFuture<GetAccessTokenRes> getAccessToken(String bearerToken);


  public class GetAccessTokenRes {
    public final Optional<AccessToken> accessToken;

    public GetAccessTokenRes(Optional<AccessToken> accessToken) {
      this.accessToken = accessToken == null ? Optional.empty() : accessToken;
    }
  }
}
