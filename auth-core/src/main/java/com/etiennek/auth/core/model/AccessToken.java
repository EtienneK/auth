package com.etiennek.auth.core.model;

import java.time.LocalDateTime;

import static com.etiennek.auth.core.Util.*;

public class AccessToken {

  private String token;
  private String clientId;
  private String userId;
  private LocalDateTime expires;

  public AccessToken(String token, String clientId, String userId) {
    this(token, clientId, userId, null);
  }

  public AccessToken(String token, String clientId, String userId, LocalDateTime expires) {
    this.token = checkNotNull(token);
    this.clientId = checkNotNull(clientId);
    this.userId = checkNotNull(userId);
    this.expires = expires;
  }

  public boolean hasExpired(LocalDateTime now) {
    return expires != null && expires.isBefore(now);
  }

}
