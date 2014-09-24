package com.etiennek.auth.core;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.etiennek.auth.core.Const.*;
import com.etiennek.auth.core.model.RequiredFunctions;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

public class OAuth2ServerConfiguration {

  private Regex regex;
  private Funcs funcs;

  private Optional<Duration> accessTokenLifetime;
  private Optional<Duration> refreshTokenLifetime;
  private Duration authCodeLifetime;
  private ImmutableList<String> supportedGrantTypes;

  private OAuth2ServerConfiguration() {
    regex = new Regex();
    funcs = new Funcs();
  }

  public Regex getRegex() {
    return regex;
  }

  public Funcs getFuncs() {
    return funcs;
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

  public ImmutableList<String> getSupportedGrantTypes() {
    return supportedGrantTypes;
  }

  public class Regex {
    private String clientId;

    public String getClientId() {
      return clientId;
    }

  }

  public class Funcs {
    private RequiredFunctions required;
    private Optional<RequiredFunctions.AuthCodeGrantType> authCode = Optional.empty();
    private Optional<RequiredFunctions.PasswordGrantType> password = Optional.empty();
    private Optional<RequiredFunctions.RefreshTokenGrantType> refreshToken = Optional.empty();
    private Optional<RequiredFunctions.ClientCredentialsGrantType> clientCreds = Optional.empty();

    public RequiredFunctions getRequired() {
      return required;
    }

    public Optional<RequiredFunctions.AuthCodeGrantType> getAuthCode() {
      return authCode;
    }

    public Optional<RequiredFunctions.PasswordGrantType> getPassword() {
      return password;
    }

    public Optional<RequiredFunctions.ClientCredentialsGrantType> getClientCreds() {
      return clientCreds;
    }

    public Optional<RequiredFunctions.RefreshTokenGrantType> getRefreshToken() {
      return refreshToken;
    }

  }

  public static class Builder {
    private OAuth2ServerConfiguration config = new OAuth2ServerConfiguration();

    private List<String> supportedGrantTypes = new ArrayList<>();

    public Builder(RequiredFunctions requiredFunctions) {
      config.funcs.required =
          Preconditions.checkNotNull(requiredFunctions, "No requiredFunctions supplied to OAuth2Server Builder");
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

    public Builder withClientIdRegex(String clientIdRegex) {
      config.regex.clientId = clientIdRegex;
      return this;
    }

    public Builder withAuthCodeGrantTypeSupport(RequiredFunctions.AuthCodeGrantType requiredFunctions) {
      if (requiredFunctions == null) {
        config.funcs.authCode = Optional.empty();
        supportedGrantTypes.remove(GRANT_AUTHORIZATION_CODE);
      } else {
        config.funcs.authCode = Optional.of(requiredFunctions);
        supportedGrantTypes.add(GRANT_AUTHORIZATION_CODE);
      };
      return this;
    }

    public Builder withPasswordGrantTypeSupport(RequiredFunctions.PasswordGrantType requiredFunctions) {
      if (requiredFunctions == null) {
        config.funcs.password = Optional.empty();
        supportedGrantTypes.remove(GRANT_PASSWORD);
      } else {
        config.funcs.password = Optional.of(requiredFunctions);
        supportedGrantTypes.add(GRANT_PASSWORD);
      };
      return this;
    }

    public Builder withClientCredentialsGrantTypeSupport(RequiredFunctions.ClientCredentialsGrantType requiredFunctions) {
      if (requiredFunctions == null) {
        config.funcs.clientCreds = Optional.empty();
        supportedGrantTypes.remove(GRANT_CLIENT_CREDENTIALS);
      } else {
        config.funcs.clientCreds = Optional.of(requiredFunctions);
        supportedGrantTypes.add(GRANT_CLIENT_CREDENTIALS);
      };
      return this;
    }

    public Builder withRefreshTokenGrantTypeSupport(RequiredFunctions.RefreshTokenGrantType requiredFunctions) {
      if (requiredFunctions == null) {
        config.funcs.refreshToken = Optional.empty();
        supportedGrantTypes.remove(GRANT_REFRESH_TOKEN);
      } else {
        config.funcs.refreshToken = Optional.of(requiredFunctions);
        supportedGrantTypes.add(GRANT_REFRESH_TOKEN);
      };
      return this;
    }

    public OAuth2ServerConfiguration build() {
      if (config.accessTokenLifetime == null) {
        config.accessTokenLifetime = Optional.of(Duration.ofHours(1));
      }
      if (config.refreshTokenLifetime == null) {
        config.refreshTokenLifetime = Optional.of(Duration.ofDays(14));
      }
      if (config.authCodeLifetime == null) {
        config.authCodeLifetime = Duration.ofSeconds(30);
      }
      if (config.regex.clientId == null) {
        config.regex.clientId = "^[A-Za-z0-9-_]{3,40}$";
      }

      config.supportedGrantTypes = ImmutableList.copyOf(supportedGrantTypes);

      return config;
    }

  }

}
