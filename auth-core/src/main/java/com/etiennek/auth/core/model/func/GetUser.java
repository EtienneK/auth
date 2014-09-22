package com.etiennek.auth.core.model.func;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.User;

@FunctionalInterface
public interface GetUser {

  CompletableFuture<GetUserRes> getUser(String username, String password);

  public class GetUserRes {
    public final Optional<User> user;

    public GetUserRes(Optional<User> user) {
      this.user = user == null ? Optional.empty() : user;
    }
  }
}
