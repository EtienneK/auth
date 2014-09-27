package com.etiennek.auth.core.model;

import java.time.LocalDateTime;

import static com.etiennek.auth.core.Util.*;

public class AuthCode {
  private String clientId;
  private String userId;
  private LocalDateTime expires;

  public AuthCode(String clientId, String userId, LocalDateTime expires) {
    this.clientId = checkNotNull(clientId);
    this.userId = checkNotNull(userId);
    this.expires = checkNotNull(expires);
  }

  public boolean hasExpired(LocalDateTime now) {
    return expires.isBefore(now);
  }

  public String getClientId() {
    return clientId;
  }

  public String getUserId() {
    return userId;
  }

}
