package com.etiennek.auth.core.model.func;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.AuthCode;

@FunctionalInterface
public interface GetAuthCode {

  CompletableFuture<GetAuthCodeRes> getAuthCode(String authCode);

  public class GetAuthCodeRes {
    public final Optional<AuthCode> authCode;

    public GetAuthCodeRes(Optional<AuthCode> authCode) {
      this.authCode = authCode == null ? Optional.empty() : authCode;
    }
  }

}
