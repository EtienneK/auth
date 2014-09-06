package com.etiennek.auth.core.model.func;

import java.util.concurrent.CompletableFuture;

@FunctionalInterface
public interface RevokeRefreshToken {
  CompletableFuture<Void> revokeRefreshToken(String refreshToken);
}
