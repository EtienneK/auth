package com.etiennek.auth.core.model;

public enum ErrorCode {
  INVALID_REQUEST, UNAUTHORIZED_CLIENT, ACCESS_DENIED, UNSUPPORTED_RESPONSE_TYPE, INVALID_SCOPE, SERVER_ERROR, TEMPORARILY_UNAVAILABLE;

  @Override
  public String toString() {
    return super.toString().toLowerCase();
  }

}
