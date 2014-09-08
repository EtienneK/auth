package com.etiennek.auth.core;

public class Const {

  // Methods
  public static final String METHOD_POST = "POST";
  
  // Media Types
  public static final String MEDIA_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";
  public static final String MEDIA_JSON = "application/json;charset=UTF-8";

  // Keys
  public static final String KEY_GRANT_TYPE = "grant_type";

  // Enums
  public enum DefaultGrantType {
    AUTHORIZATION_CODE, PASSWORD, REFRESH_TOKEN, CLIENT_CREDENTIALS;

    @Override
    public String toString() {
      return super.toString()
                  .toLowerCase();
    }

  }

}
