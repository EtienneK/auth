package com.etiennek.auth.core;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import com.etiennek.auth.core.Const.DefaultGrantType;
import com.etiennek.auth.core.model.RequiredFunctions;
import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.model.func.GenerateToken.GenerateTokenRes;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

public class OAuth2ServerConfiguration {

  private Executor executor;
  private Funcs funcs;

  private Consumer<Exception> debug;
  private Optional<Duration> accessTokenLifetime;
  private Optional<Duration> refreshTokenLifetime;
  private Duration authCodeLifetime;
  private Pattern clientIdRegex;
  private ImmutableList<String> supportedGrantTypes;

  private OAuth2ServerConfiguration() {
    funcs = new Funcs();
  }

  public Executor getExecutor() {
    return executor;
  }

  public Funcs getFuncs() {
    return funcs;
  }

  public Consumer<Exception> getDebug() {
    return debug;
  }

  public Optional<Duration> getAccessTokenLifetime() {
    return accessTokenLifetime;
  }

  public Optional<Duration> getRefreshTokenLifetime() {
    return refreshTokenLifetime;
  }

  public Duration getAuthCodeLifetime() {
    return authCodeLifetime;
  }

  public Pattern getClientIdRegex() {
    return clientIdRegex;
  }

  public ImmutableList<String> getSupportedGrantTypes() {
    return supportedGrantTypes;
  }

  public class Funcs {
    private RequiredFunctions req;
    private Optional<RequiredFunctions.AuthCodeGrantType> authCode = Optional.empty();
    private Optional<RequiredFunctions.PasswordGrantType> password = Optional.empty();
    private Optional<RequiredFunctions.RefreshTokenGrantType> refreshToken = Optional.empty();
    private RequiredFunctions.TokenGeneration tokenGeneration;

    public RequiredFunctions getReq() {
      return req;
    }

    public Optional<RequiredFunctions.AuthCodeGrantType> getAuthCode() {
      return authCode;
    }

    public Optional<RequiredFunctions.PasswordGrantType> getPassword() {
      return password;
    }

    public Optional<RequiredFunctions.RefreshTokenGrantType> getRefreshToken() {
      return refreshToken;
    }

    public RequiredFunctions.TokenGeneration getTokenGeneration() {
      return tokenGeneration;
    }
  }

  public static class Builder {
    private OAuth2ServerConfiguration config = new OAuth2ServerConfiguration();

    private List<String> supportedGrantTypes = new ArrayList<>();

    public Builder(RequiredFunctions requiredFunctions) {
      config.funcs.req =
          requiredFunctions =
              Preconditions.checkNotNull(requiredFunctions, "No requiredFunctions supplied to OAuth2Server Builder");
    }

    public Builder withExecutor(Executor executor) {
      config.executor = executor;
      return this;
    }

    public Builder withDebug(Consumer<Exception> debug) {
      config.debug = debug;
      return this;
    }

    public Builder withAccessTokenLifetime(Duration accessTokenLifetime) {
      config.accessTokenLifetime = accessTokenLifetime == null ? Optional.empty() : Optional.of(accessTokenLifetime);
      return this;
    }

    public Builder withRefreshTokenLifetime(Duration refreshTokenLifetime) {
      config.refreshTokenLifetime = refreshTokenLifetime == null ? Optional.empty() : Optional.of(refreshTokenLifetime);
      return this;
    }

    public Builder withAuthCodeLifetime(Duration authCodeLifetime) {
      config.authCodeLifetime = authCodeLifetime;
      return this;
    }

    public Builder withClientIdRegex(Pattern clientIdRegex) {
      config.clientIdRegex = clientIdRegex;
      return this;
    }

    public Builder withAuthCodeGrantTypeSupport(RequiredFunctions.AuthCodeGrantType requiredFunctions) {
      if (requiredFunctions == null) {
        config.funcs.authCode = Optional.empty();
        supportedGrantTypes.remove(DefaultGrantType.AUTHORIZATION_CODE.toString());
      } else {
        config.funcs.authCode = Optional.of(requiredFunctions);
        supportedGrantTypes.add(DefaultGrantType.AUTHORIZATION_CODE.toString());
      };
      return this;
    }

    public Builder withPasswordGrantTypeSupport(RequiredFunctions.PasswordGrantType requiredFunctions) {
      if (requiredFunctions == null) {
        config.funcs.password = Optional.empty();
        supportedGrantTypes.remove(DefaultGrantType.PASSWORD.toString());
      } else {
        config.funcs.password = Optional.of(requiredFunctions);
        supportedGrantTypes.add(DefaultGrantType.PASSWORD.toString());
      };
      return this;
    }

    public Builder withRefreshTokenGrantTypeSupport(RequiredFunctions.RefreshTokenGrantType requiredFunctions) {
      if (requiredFunctions == null) {
        config.funcs.refreshToken = Optional.empty();
        supportedGrantTypes.remove(DefaultGrantType.REFRESH_TOKEN.toString());
      } else {
        config.funcs.refreshToken = Optional.of(requiredFunctions);
        supportedGrantTypes.add(DefaultGrantType.REFRESH_TOKEN.toString());
      };
      return this;
    }

    public Builder withTokenGenerationSupport(RequiredFunctions.TokenGeneration requiredFunctions) {
      config.funcs.tokenGeneration = requiredFunctions;
      return this;
    }

    public OAuth2ServerConfiguration build() {
      if (config.executor == null) {
        config.executor = ForkJoinPool.commonPool();
      }
      if (config.debug == null) {
        config.debug = (exception) -> {
          exception.printStackTrace();
        };
      }
      if (config.accessTokenLifetime == null) {
        config.accessTokenLifetime = Optional.of(Duration.ofHours(1));
      }
      if (config.refreshTokenLifetime == null) {
        config.refreshTokenLifetime = Optional.of(Duration.ofDays(14));
      }
      if (config.authCodeLifetime == null) {
        config.authCodeLifetime = Duration.ofSeconds(30);
      }
      if (config.clientIdRegex == null) {
        config.clientIdRegex = Pattern.compile("^[a-z0-9-_]{3,40}$");
      }
      if (config.funcs.tokenGeneration == null) {
        config.funcs.tokenGeneration = this::generateTokenDefault;
      }

      config.supportedGrantTypes = ImmutableList.copyOf(supportedGrantTypes);

      return config;
    }

    private CompletableFuture<GenerateTokenRes> generateTokenDefault(TokenType tokenType) {
      CompletableFuture<GenerateTokenRes> ret = new CompletableFuture<>();
      try {
        byte[] randomBytes = new byte[32];
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.nextBytes(randomBytes);
        ret.complete(new GenerateTokenRes(Base64.getEncoder()
                                                .encodeToString(randomBytes)));
      } catch (NoSuchAlgorithmException e) {
        // TODO: Error handling
        ret.completeExceptionally(e);
      }
      return ret;
    }
  }

}
