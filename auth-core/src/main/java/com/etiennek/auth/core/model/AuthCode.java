package com.etiennek.auth.core.model;

import java.time.LocalDateTime;

import com.google.common.base.Preconditions;

public class AuthCode {
  private String clientId;
  private String userId;
  private LocalDateTime expires;

  public AuthCode(String clientId, String userId, LocalDateTime expires) {
    this.clientId = Preconditions.checkNotNull(clientId);
    this.userId = Preconditions.checkNotNull(userId);
    this.expires = Preconditions.checkNotNull(expires);
  }

  public boolean hasExpired(LocalDateTime now) {
    return expires.isBefore(now);
  }

}
