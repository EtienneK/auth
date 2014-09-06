package com.etiennek.auth.core.model.func;

import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.RefreshToken;

@FunctionalInterface
public interface GetRefreshToken {
  CompletableFuture<GetRefreshTokenRes> getRefreshToken(String refreshToken);

  public class GetRefreshTokenRes {
    public final RefreshToken refreshToken;

    public GetRefreshTokenRes(RefreshToken refreshToken) {
      this.refreshToken = refreshToken;
    }
  }
}
