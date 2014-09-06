package com.etiennek.auth.core.model.func;

import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.User;

@FunctionalInterface
public interface SaveAccessToken {
  CompletableFuture<Void> saveAccessToken(String accessToken, String clientId, User user, LocalDateTime expires);
}
