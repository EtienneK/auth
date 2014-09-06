package com.etiennek.auth.core.model.func;

import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.GrantType;

@FunctionalInterface
public interface IsGrantTypeAllowed {

  CompletableFuture<IsGrantTypeAllowedRes> isGrantTypeAllowed(String clientId, GrantType grantType);

  public class IsGrantTypeAllowedRes {
    public final boolean allowed;

    public IsGrantTypeAllowedRes(boolean allowed) {
      this.allowed = allowed;
    }
  }

}
