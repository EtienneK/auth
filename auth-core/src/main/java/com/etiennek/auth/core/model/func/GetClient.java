package com.etiennek.auth.core.model.func;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.Client;

@FunctionalInterface
public interface GetClient {

  CompletableFuture<GetClientRes> getClient(String clientId, String clientSecret);

  public class GetClientRes {
    public final Optional<Client> client;

    public GetClientRes(Optional<Client> client) {
      this.client = client == null ? Optional.empty() : client;
    }
  }

}
