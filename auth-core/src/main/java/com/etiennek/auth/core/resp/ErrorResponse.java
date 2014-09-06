package com.etiennek.auth.core.resp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import com.etiennek.auth.core.Response;
import com.etiennek.auth.core.model.ErrorCode;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;

public class ErrorResponse extends Response {

  private static ImmutableMap<String, String> header = new ImmutableMap.Builder<String, String>()
      .put("Content-Type", "application/x-www-form-urlencoded").put("Cache-Control", "no-store")
      .put("Pragma", "no-cache").build();

  private static String body = "error=%s&error_description=%s";

  public ErrorResponse(ErrorCode errorCode, String errorDescription) {
    super(errorCode.getHttpCode(), header, String.format(body, errorCode, encode(errorDescription)));
    
    // TODO: Add WWW-Authenticate header for INVALID_CLIENT Error Code: 5.2 of the RFC
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
