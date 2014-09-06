package com.etiennek.auth.core.model;

import com.etiennek.auth.core.model.func.*;

public interface RequiredFunctions extends GetAccessToken, GetClient, IsGrantTypeAllowed,
    SaveAccessToken {

  public interface AuthCodeGrantType extends GetAuthCode {
  }

  public interface PasswordGrantType extends GetUser {
  }

  public interface RefreshTokenGrantType extends SaveRefreshToken, GetRefreshToken,
      RevokeRefreshToken {
  }

  public interface TokenGeneration extends GenerateToken {
  }
}
