package com.etiennek.auth.core;

import com.etiennek.auth.core.model.RequiredFunctions;

public class Verify {
  private OAuth2ServerConfiguration config;
  private FormRequest request;
  private RequiredFunctions requiredFuncs;

  Verify(OAuth2ServerConfiguration config, FormRequest request) {
    this.config = config;
    this.request = request;
    this.requiredFuncs = config.getFuncs()
                               .getRequired();
  }
  
  // TODO

}
