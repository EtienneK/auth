package com.etiennek.auth.core.model.func;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

@FunctionalInterface
public interface SaveAccessToken {
  CompletableFuture<Void> saveAccessToken(String accessToken, String clientId, String userId,
      Optional<LocalDateTime> expires);
}
