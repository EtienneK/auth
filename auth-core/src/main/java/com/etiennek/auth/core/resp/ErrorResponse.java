package com.etiennek.auth.core.resp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import com.etiennek.auth.core.Const;
import com.etiennek.auth.core.Response;
import com.etiennek.auth.core.model.ErrorCode;

public class ErrorResponse extends Response {
  private static String body = "error=%s&error_description=%s";

  public ErrorResponse(ErrorCode errorCode, String errorDescription) {
    super(errorCode.getHttpCode(), header(errorCode), String.format(body, errorCode, encode(errorDescription)));

    // TODO: Add WWW-Authenticate header for INVALID_CLIENT Error Code: 5.2 of the RFC
  }

  private static Map<String, String[]> header(ErrorCode errorCode) {
    Map<String, String[]> ret = new HashMap<>();
    ret.put("Content-Type", new String[] {Const.MEDIA_X_WWW_FORM_URLENCODED});
    ret.put("Cache-Control", new String[] {"no-store"});
    ret.put("Pragma", new String[] {"no-cache"});
    if (errorCode == ErrorCode.INVALID_CLIENT) {
      ret.put("WWW-Authenticate", new String[] {"Basic realm=\"Service\""});
    }
    return ret;
  }

  private static String encode(String toEncode) {
    try {
      return URLEncoder.encode(toEncode, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      // Should never happen
      throw new RuntimeException(e);
    }
  }

}
