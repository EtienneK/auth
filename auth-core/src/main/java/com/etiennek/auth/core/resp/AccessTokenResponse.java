package com.etiennek.auth.core.resp;

import java.time.Duration;
import java.util.Optional;

import com.etiennek.auth.core.Const;
import com.etiennek.auth.core.Response;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;

public class AccessTokenResponse extends Response {
  private static ImmutableMap<String, String> header = new ImmutableMap.Builder<String, String>().put("Content-Type",
      Const.MEDIA_JSON)
                                                                                                 .put("Cache-Control",
                                                                                                     "no-store")
                                                                                                 .put("Pragma",
                                                                                                     "no-cache")
                                                                                                 .build();

  public AccessTokenResponse(String accessToken, Optional<Duration> accessTokenLifetime, Optional<String> refreshToken) {
    super(200, header, generateBody(accessToken, accessTokenLifetime, refreshToken));
  }

  private static String generateBody(String accessToken, Optional<Duration> accessTokenLifetime,
      Optional<String> refreshToken) {
    Preconditions.checkNotNull(accessToken);

    StringBuilder body = new StringBuilder();
    body.append("{\"access_token\":\"")
        .append(accessToken)
        .append("\",\"token_type\":\"bearer\"");
    if (accessTokenLifetime.isPresent()) {
      body.append(",\"expires_in\":")
          .append(accessTokenLifetime.get()
                                     .getSeconds());
    }
    if (refreshToken.isPresent()) {
      body.append(",\"refresh_token\":\"")
          .append(refreshToken.get())
          .append("\"");
    }
    body.append("}");
    return body.toString();
  }

}
