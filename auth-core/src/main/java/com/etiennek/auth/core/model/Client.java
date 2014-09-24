package com.etiennek.auth.core.model;

public class Client {
  private String id;
  private String secret;

  public Client(String id, String secret) {
    this.id = id;
    this.secret = secret;
  }

  public String getId() {
    return id;
  }

  public String getSecret() {
    return secret;
  }

}
