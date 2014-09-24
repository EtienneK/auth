package com.etiennek.auth.core.model.func;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.RefreshToken;

@FunctionalInterface
public interface GetRefreshToken {
  CompletableFuture<GetRefreshTokenRes> getRefreshToken(String refreshToken);

  public class GetRefreshTokenRes {
    public final Optional<RefreshToken> refreshToken;

    public GetRefreshTokenRes(Optional<RefreshToken> refreshToken) {
      this.refreshToken = refreshToken == null ? Optional.empty() : refreshToken;
    }
  }
}
