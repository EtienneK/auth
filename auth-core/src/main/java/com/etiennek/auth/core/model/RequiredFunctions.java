package com.etiennek.auth.core.model;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

import com.etiennek.auth.core.model.func.*;

public interface RequiredFunctions extends GetAccessToken, GetClient, IsGrantTypeAllowed, SaveAccessToken,
    GenerateToken, GetNow {

  default LocalDateTime getNow() {
    return LocalDateTime.now();
  }

  default CompletableFuture<GenerateTokenRes> generateToken(TokenType tokenType) {
    CompletableFuture<GenerateTokenRes> ret = new CompletableFuture<>();
    try {
      byte[] randomBytes = new byte[32];
      SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
      secureRandom.nextBytes(randomBytes);
      ret.complete(new GenerateTokenRes(Base64.getEncoder()
                                              .encodeToString(randomBytes)));
    } catch (NoSuchAlgorithmException e) {
      ret.completeExceptionally(e);
    }
    return ret;
  }

  public interface AuthCodeGrantType extends GetAuthCode {
  }

  public interface PasswordGrantType extends GetUser {
  }

  public interface ClientCredentialsGrantType extends GetUserFromClient {
  }

  public interface RefreshTokenGrantType extends SaveRefreshToken, GetRefreshToken, RevokeRefreshToken {
  }

}
