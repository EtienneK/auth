package com.etiennek.auth.core.model;

import java.time.LocalDateTime;

import com.google.common.base.Preconditions;

public class AccessToken {

  private String id;
  private LocalDateTime expires;

  public AccessToken(String userId) {
    this(userId, null);
  }

  public AccessToken(String id, LocalDateTime expires) {
    this.id = Preconditions.checkNotNull(id);
    this.expires = expires;
  }

  public boolean hasExpired(LocalDateTime now) {
    return expires != null && expires.isBefore(now);
  }


}
