package com.etiennek.auth.core;

import com.etiennek.auth.core.model.ErrorCode;

class OAuth2Exception extends RuntimeException {

  private static final long serialVersionUID = 8964296846977980153L;

  private ErrorCode errorCode;

  public OAuth2Exception(ErrorCode errorCode, String message) {
    super(message);
    this.errorCode = errorCode;
  }

  public OAuth2Exception(ErrorCode errorCode, String message, Throwable cause) {
    super(message, cause);
    this.errorCode = errorCode;
  }

  public ErrorCode getErrorCode() {
    return errorCode;
  }

}
