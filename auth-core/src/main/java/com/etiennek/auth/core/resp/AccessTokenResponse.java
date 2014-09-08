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
    body.append("{\n")
        .append("\t\"access_token\":\"")
        .append(accessToken)
        .append("\",\n")
        .append("\t\"token_type\":\"")
        .append("bearer")
        .append("\",\n");
    if (accessTokenLifetime.isPresent()) {
      body.append("\t\"expires_in\":\"")
          .append(accessTokenLifetime.get()
                                     .getSeconds())
          .append("\",\n");
    }
    if (refreshToken.isPresent()) {
      body.append("\t\"refresh_token\":\"")
          .append(refreshToken.get())
          .append("\"\n");
    }
    body.append("}");
    return body.toString();
  }

}
