package com.etiennek.auth.core.model.func;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.User;

@FunctionalInterface
public interface SaveRefreshToken {

  CompletableFuture<Void> saveRefreshToken(String refreshToken, String clientId, String userId,
      Optional<LocalDateTime> expires);

}
