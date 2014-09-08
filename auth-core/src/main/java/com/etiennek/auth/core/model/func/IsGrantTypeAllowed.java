package com.etiennek.auth.core.model.func;

import java.util.concurrent.CompletableFuture;

@FunctionalInterface
public interface IsGrantTypeAllowed {

  CompletableFuture<IsGrantTypeAllowedRes> isGrantTypeAllowed(String clientId, String grantType);

  public class IsGrantTypeAllowedRes {
    public final boolean allowed;

    public IsGrantTypeAllowedRes(boolean allowed) {
      this.allowed = allowed;
    }
  }

}
