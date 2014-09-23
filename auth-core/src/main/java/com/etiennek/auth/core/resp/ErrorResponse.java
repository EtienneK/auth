package com.etiennek.auth.core.resp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import com.etiennek.auth.core.Const;
import com.etiennek.auth.core.Response;
import com.etiennek.auth.core.model.ErrorCode;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMap.Builder;

public class ErrorResponse extends Response {
  private static String body = "error=%s&error_description=%s";

  public ErrorResponse(ErrorCode errorCode, String errorDescription) {
    super(errorCode.getHttpCode(), header(errorCode), String.format(body, errorCode, encode(errorDescription)));

    // TODO: Add WWW-Authenticate header for INVALID_CLIENT Error Code: 5.2 of the RFC
  }

  private static ImmutableMap<String, String> header(ErrorCode errorCode) {
    ImmutableMap.Builder<String, String> builder =
        new Builder<String, String>().put("Content-Type", Const.MEDIA_X_WWW_FORM_URLENCODED)
                                     .put("Cache-Control", "no-store")
                                     .put("Pragma", "no-cache");
    if (errorCode == ErrorCode.INVALID_CLIENT) {
      builder.put("WWW-Authenticate", "Basic realm=\"Service\"");
    }
    return builder.build();
  }

  private static String encode(String toEncode) {
    try {
      return URLEncoder.encode(toEncode, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      // Should never happen
      throw Throwables.propagate(e);
    }
  }

}
