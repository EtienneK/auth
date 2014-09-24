package com.etiennek.auth.core.model;

import java.time.LocalDateTime;

import com.google.common.base.Preconditions;

public class AccessToken {

  private String token;
  private String clientId;
  private String userId;
  private LocalDateTime expires;

  public AccessToken(String token, String clientId, String userId) {
    this(token, clientId, userId, null);
  }

  public AccessToken(String token, String clientId, String userId, LocalDateTime expires) {
    this.token = Preconditions.checkNotNull(token);
    this.clientId = Preconditions.checkNotNull(clientId);
    this.userId = Preconditions.checkNotNull(userId);
    this.expires = expires;
  }

  public boolean hasExpired(LocalDateTime now) {
    return expires != null && expires.isBefore(now);
  }

}
