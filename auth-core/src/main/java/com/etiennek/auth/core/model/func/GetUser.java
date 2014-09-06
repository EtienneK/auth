package com.etiennek.auth.core.model.func;

import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.User;

@FunctionalInterface
public interface GetUser {

  CompletableFuture<GetUserRes> getUser(String username, String password);

  public class GetUserRes {
    public final User user;

    public GetUserRes(User user) {
      super();
      this.user = user;
    }
  }
}
