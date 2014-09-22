package com.etiennek.auth.core.model;

import java.time.LocalDateTime;

import com.google.common.base.Preconditions;

public class AccessToken {

  private String userId;
  private LocalDateTime expires;

  public AccessToken(String userId) {
    this(userId, null);
  }

  public AccessToken(String userId, LocalDateTime expires) {
    this.userId = Preconditions.checkNotNull(userId);
    this.expires = expires;
  }

  public boolean hasExpired(LocalDateTime now) {
    return expires != null && expires.isBefore(now);
  }


}
