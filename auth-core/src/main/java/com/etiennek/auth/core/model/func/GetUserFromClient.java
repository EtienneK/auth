package com.etiennek.auth.core.model.func;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.User;

@FunctionalInterface
public interface GetUserFromClient {

  CompletableFuture<GetUserFromClientRes> getUserFromClient(String clientId, String clientSecret);

  public class GetUserFromClientRes {
    public final Optional<User> user;

    public GetUserFromClientRes(Optional<User> user) {
      this.user = user == null ? Optional.empty() : user;
    }
    
  }
}
