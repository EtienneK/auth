package com.etiennek.auth.core;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import org.junit.Assert;

import com.etiennek.auth.core.model.Client;
import com.etiennek.auth.core.model.RefreshToken;
import com.etiennek.auth.core.model.RequiredFunctions;
import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.model.User;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import com.google.gson.Gson;

public abstract class TestBase {

  public static final LocalDateTime NOW = LocalDateTime.of(2014, 9, 24, 11, 05, 28, 382);
  public static final Duration ACCESS_TOKEN_LIFETIME = Duration.ofHours(2);
  public static final String ACCESS_TOKEN = "fewEWFefwhj23bnjklnhfew";
  public static final String REFRESH_TOKEN = "erjkhh#$%#334345jkhgerkn";
  public static final Duration REFRESH_TOKEN_LIFETIME = Duration.ofDays(21);
  public static final String USER_ID = "234535";
  public static final String USER_USERNAME = "Joe_THE_USAH";
  public static final String USER_PASSWORD = "Joe's 4wesome PASSW0Rd";
  public static final String CLIENT_ID = "some_client_YAY-12334";
  public static final String CLIENT_SECRET = "and A secret FOR THAT client";

  Gson gson = new Gson();

  RequiredFunctions requiredFunctions;
  RequiredFunctions.PasswordGrantType passwordRequiredFunctions;
  RequiredFunctions.RefreshTokenGrantType refreshTokenRequiredFunctions;

  private OAuth2ServerConfiguration config;
  OAuth2ServerConfiguration.Builder configBuilder;

  LocalDateTime now;
  boolean isGrantTypeAllowed;
  Optional<Client> client;
  Optional<User> user;
  Optional<RefreshToken> refreshToken;

  Response actualResponse;

  public void init() {
    now = NOW;
    actualResponse = null;

    isGrantTypeAllowed = true;
    client = Optional.of(new Client(CLIENT_ID, CLIENT_SECRET));
    user = Optional.of(new User(USER_ID, USER_USERNAME, USER_PASSWORD));
    refreshToken = Optional.of(new RefreshToken(CLIENT_ID, USER_ID));

    requiredFunctions = new RequiredFunctions() {
      @Override
      public LocalDateTime getNow() {
        return now;
      }

      @Override
      public CompletableFuture<GetAccessTokenRes> getAccessToken(String bearerToken) {
        // TODO: Move to non required functions
        throw new UnsupportedOperationException();
      }

      @Override
      public CompletableFuture<GetClientRes> getClient(String clientId, String clientSecret) {
        Assert.assertEquals(CLIENT_ID, clientId);
        Assert.assertEquals(CLIENT_SECRET, clientSecret);
        return CompletableFuture.completedFuture(new GetClientRes(client));
      }

      @Override
      public CompletableFuture<IsGrantTypeAllowedRes> isGrantTypeAllowed(String clientId, String grantType) {
        Assert.assertEquals(CLIENT_ID, clientId);
        Assert.assertNotNull(grantType);
        return CompletableFuture.completedFuture(new IsGrantTypeAllowedRes(isGrantTypeAllowed));
      }

      @Override
      public CompletableFuture<Void> saveAccessToken(String accessToken, String clientId, String userId,
          Optional<LocalDateTime> expires) {
        Assert.assertEquals(ACCESS_TOKEN, accessToken);
        Assert.assertEquals(CLIENT_ID, clientId);
        Assert.assertEquals(USER_ID, userId);
        Assert.assertEquals(config.getAccessTokenLifetime()
                                  .isPresent(), expires.isPresent());

        if (config.getAccessTokenLifetime()
                  .isPresent()) {
          Assert.assertTrue(now.plus(ACCESS_TOKEN_LIFETIME)
                               .minusNanos(1)
                               .isBefore(expires.get()));
          Assert.assertTrue(now.plus(ACCESS_TOKEN_LIFETIME)
                               .plusNanos(1)
                               .isAfter(expires.get()));
        }
        return CompletableFuture.completedFuture(null);
      }

      @Override
      public CompletableFuture<GenerateTokenRes> generateToken(TokenType tokenType) {
        CompletableFuture<GenerateTokenRes> ret = new CompletableFuture<>();
        new Thread("generateTokenThread") {
          public void run() {
            try {
              sleep(100);
            } catch (InterruptedException e) {
              e.printStackTrace();
            }
            if (tokenType == TokenType.ACCESS)
              ret.complete(new GenerateTokenRes(ACCESS_TOKEN));
            else
              ret.complete(new GenerateTokenRes(REFRESH_TOKEN));
          };
        }.start();
        return ret;
      }
    };

    passwordRequiredFunctions = new RequiredFunctions.PasswordGrantType() {
      @Override
      public CompletableFuture<GetUserRes> getUser(String username, String password) {
        Assert.assertEquals(USER_USERNAME, username);
        Assert.assertEquals(USER_PASSWORD, password);
        return CompletableFuture.completedFuture(new GetUserRes(user));
      }
    };

    refreshTokenRequiredFunctions = new RequiredFunctions.RefreshTokenGrantType() {
      @Override
      public CompletableFuture<Void> revokeRefreshToken(String refreshToken) {
        Assert.assertEquals(REFRESH_TOKEN, refreshToken);
        return CompletableFuture.completedFuture(null);
      }

      @Override
      public CompletableFuture<GetRefreshTokenRes> getRefreshToken(String rt) {
        return CompletableFuture.completedFuture(new GetRefreshTokenRes(refreshToken));
      }

      @Override
      public CompletableFuture<Void> saveRefreshToken(String refreshToken, String clientId, String userId,
          Optional<LocalDateTime> expires) {

        Assert.assertEquals(REFRESH_TOKEN, refreshToken);
        Assert.assertEquals(CLIENT_ID, clientId);
        Assert.assertEquals(USER_ID, userId);
        Assert.assertEquals(config.getRefreshTokenLifetime()
                                  .isPresent(), expires.isPresent());

        if (config.getRefreshTokenLifetime()
                  .isPresent()) {
          Assert.assertTrue(now.plus(REFRESH_TOKEN_LIFETIME)
                               .minusNanos(1)
                               .isBefore(expires.get()));
          Assert.assertTrue(now.plus(REFRESH_TOKEN_LIFETIME)
                               .plusNanos(1)
                               .isAfter(expires.get()));
        }
        return CompletableFuture.completedFuture(null);
      }
    };

    configBuilder =
        new OAuth2ServerConfiguration.Builder(requiredFunctions).withPasswordGrantTypeSupport(passwordRequiredFunctions)
                                                                .withRefreshTokenGrantTypeSupport(
                                                                    refreshTokenRequiredFunctions)
                                                                .withAccessTokenLifetime(ACCESS_TOKEN_LIFETIME)
                                                                .withRefreshTokenLifetime(REFRESH_TOKEN_LIFETIME);
  }

  OAuth2Server server() {
    config = configBuilder.build();
    return new OAuth2Server(config);
  }

  ImmutableMap.Builder<String, String> imbs() {
    return new ImmutableMap.Builder<String, String>();
  }

  static String encode(String toEncode) {
    try {
      return URLEncoder.encode(toEncode, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      // Should never happen
      throw Throwables.propagate(e);
    }
  }

  ImmutableMap<String, String> jsonResponseHeader() {
    return imbs().put("Content-Type", "application/json;charset=UTF-8")
                 .put("Cache-Control", "no-store")
                 .put("Pragma", "no-cache")
                 .build();
  }

  ImmutableMap<String, String> urlFormEncodedResponseHeader() {
    return urlFormEncodedResponseHeader(null);
  }

  ImmutableMap<String, String> urlFormEncodedResponseHeader(Map<String, String> extraHeaders) {
    if (extraHeaders == null)
      extraHeaders = new HashMap<>();
    return imbs().put("Content-Type", "application/x-www-form-urlencoded")
                 .put("Cache-Control", "no-store")
                 .put("Pragma", "no-cache")
                 .putAll(extraHeaders)
                 .build();
  }

  void assertResponse(int expectedResponseCode, Map<String, String> expectedResponseHeader,
      String expectedResponseBody, Response actualResponse) {
    assertEquals(expectedResponseCode, actualResponse.getCode());
    if (expectedResponseHeader != null)
      assertEquals(expectedResponseHeader, actualResponse.getHeader());
    if (expectedResponseBody != null)
      assertEquals(expectedResponseBody, actualResponse.getBody());
  }

  Request newPasswordGrantTypeRequest(String clientId, String clientSecret, String userId, String userPassword) {
    ImmutableMap<String, String> requestHeader =
        imbs().put("Authorization", "Basic " + Base64.getEncoder()
                                                     .encodeToString((clientId + ":" + clientSecret).getBytes()))
              .put("Content-Type", "application/x-www-form-urlencoded")
              .build();
    String requestBody = "grant_type=password&username=" + encode(userId) + "&password=" + encode(userPassword);
    return new Request("POST", requestHeader, requestBody);
  }

}
