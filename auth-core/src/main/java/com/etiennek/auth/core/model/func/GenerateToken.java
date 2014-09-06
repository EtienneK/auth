package com.etiennek.auth.core.model.func;

import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.TokenType;

@FunctionalInterface
public interface GenerateToken {

  CompletableFuture<GenerateTokenRes> generateToken(TokenType tokenType);

  public class GenerateTokenRes {
    public final String token;

    public GenerateTokenRes(String token) {
      super();
      this.token = token;
    }
  }
}
