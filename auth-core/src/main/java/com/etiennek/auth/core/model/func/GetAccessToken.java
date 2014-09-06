package com.etiennek.auth.core.model.func;

import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.AccessToken;

@FunctionalInterface
public interface GetAccessToken {
  CompletableFuture<GetAccessTokenRes> getAccessToken(String bearerToken);


  public class GetAccessTokenRes {
    public final AccessToken accessToken;

    public GetAccessTokenRes(AccessToken accessToken) {
      this.accessToken = accessToken;
    }
  }
}
