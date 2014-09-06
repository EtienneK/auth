package com.etiennek.auth.core.model;

import java.time.LocalDateTime;

import com.google.common.base.Preconditions;

public class RefreshToken {
  private String clientId;
  private String userId;
  private LocalDateTime expires;

  public RefreshToken(String clientId, String userId) {
    this(clientId, userId, null);
  }

  public RefreshToken(String clientId, String userId, LocalDateTime expires) {
    this.clientId = Preconditions.checkNotNull(clientId);
    this.userId = Preconditions.checkNotNull(userId);
    this.expires = expires;
  }

  public boolean hasExpired(LocalDateTime now) {
    return expires != null && expires.isBefore(now);
  }
}
