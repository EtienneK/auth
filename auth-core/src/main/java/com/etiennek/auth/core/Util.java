package com.etiennek.auth.core;

import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

public class Util {

  public static boolean isNullOrEmpty(Object[] arr) {
    return arr == null || arr.length == 0;
  }

  public static <T> T checkNotNull(T toCheck) {
    return checkNotNull(toCheck, null);
  }

  public static <T> T checkNotNull(T toCheck, String message) {
    if (toCheck == null) {
      throw new NullPointerException(message);
    }
    return toCheck;
  }

  static Map<String, String[]> toCaseInsensitiveMap(Map<String, String[]> map) {
    checkNotNull(map);
    Map<String, String[]> ret = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    ret.putAll(map);
    return ret;
  }

  static Optional<String[]> getBasicAuthCredentialsHeader(String[] authHeaderValueArr) {
    try {
      String authHeaderValue = isNullOrEmpty(authHeaderValueArr) ? "" : authHeaderValueArr[0].trim();
      if (!authHeaderValue.toLowerCase()
                          .startsWith("basic ")) {
        return Optional.empty();
      }
      authHeaderValue = authHeaderValue.substring(5)
                                       .trim();
      authHeaderValue = new String(Base64.getDecoder()
                                         .decode(authHeaderValue));
      String[] usernameAndPassword = authHeaderValue.split(":");
      if (usernameAndPassword.length != 2) {
        return Optional.empty();
      }
      return Optional.of(usernameAndPassword);
    } catch (RuntimeException e) {
      return Optional.empty();
    }
  }

}
