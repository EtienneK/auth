package com.etiennek.auth.core.model;

import java.time.LocalDateTime;

import static com.etiennek.auth.core.Util.*;

public class RefreshToken {
  private String clientId;
  private String userId;
  private LocalDateTime expires;

  public RefreshToken(String clientId, String userId) {
    this(clientId, userId, null);
  }

  public RefreshToken(String clientId, String userId, LocalDateTime expires) {
    this.clientId = checkNotNull(clientId);
    this.userId = checkNotNull(userId);
    this.expires = expires;
  }

  public String getClientId() {
    return clientId;
  }

  public String getUserId() {
    return userId;
  }

  public boolean hasExpired(LocalDateTime now) {
    return expires != null && expires.isBefore(now);
  }

}
