package com.etiennek.auth.core.model.func;

import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.AuthCode;

@FunctionalInterface
public interface GetAuthCode {

  CompletableFuture<GetAuthCodeRes> getAuthCode(String authCode);

  public class GetAuthCodeRes {
    public final AuthCode authCode;

    public GetAuthCodeRes(AuthCode authCode) {
      this.authCode = authCode;
    }
  }

}
