package com.etiennek.auth.core.resp;

import static com.etiennek.auth.core.Util.*;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import com.etiennek.auth.core.Const;
import com.etiennek.auth.core.Response;

public class AccessTokenResponse extends Response {
  private static final Map<String, String[]> header = new LinkedHashMap<>();
  static {
    header.put("Content-Type", new String[] {Const.MEDIA_JSON});
    header.put("Cache-Control", new String[] {"no-store"});
    header.put("Pragma", new String[] {"no-cache"});
  }

  public AccessTokenResponse(String accessToken, Optional<Duration> accessTokenLifetime, Optional<String> refreshToken) {
    super(200, header, generateBody(accessToken, accessTokenLifetime, refreshToken));
  }

  private static String generateBody(String accessToken, Optional<Duration> accessTokenLifetime,
      Optional<String> refreshToken) {
    checkNotNull(accessToken);

    StringBuilder body = new StringBuilder();
    body.append("{\"access_token\":\"")
        .append(accessToken)
        .append("\",\"token_type\":\"bearer\"");
    if (accessTokenLifetime != null && accessTokenLifetime.isPresent()) {
      body.append(",\"expires_in\":")
          .append(accessTokenLifetime.get()
                                     .getSeconds());
    }
    if (refreshToken != null && refreshToken.isPresent()) {
      body.append(",\"refresh_token\":\"")
          .append(refreshToken.get())
          .append("\"");
    }
    body.append("}");
    return body.toString();
  }

}
