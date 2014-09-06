package com.etiennek.auth.core.model;

public enum ErrorCode {
  INVALID_REQUEST(400), UNAUTHORIZED_CLIENT(401), ACCESS_DENIED(401), UNSUPPORTED_RESPONSE_TYPE(415), INVALID_SCOPE(400), SERVER_ERROR(
      500), TEMPORARILY_UNAVAILABLE(503), INVALID_CLIENT(401), INVALID_GRANT(400), UNSUPPORTED_GRANT_TYPE(400);

  private int httpCode;

  ErrorCode(int httpCode) {
    this.httpCode = httpCode;
  }

  public int getHttpCode() {
    return httpCode;
  }

  @Override
  public String toString() {
    return super.toString().toLowerCase();
  }

}
