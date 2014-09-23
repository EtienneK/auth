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

import com.etiennek.auth.core.model.AccessToken;
import com.etiennek.auth.core.model.Client;
import com.etiennek.auth.core.model.RefreshToken;
import com.etiennek.auth.core.model.RequiredFunctions;
import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.model.User;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import com.google.gson.Gson;

public abstract class TestBase {

  public static final Duration ACCESS_TOKEN_LIFETIME = Duration.ofHours(2);
  public static final String ACCESS_TOKEN = "fewEWFefwhj23bnjklnhfew";
  public static final String REFRESH_TOKEN = "erjkhh#$%#334345jkhgerkn";
  public static final Duration REFRESH_TOKEN_LIFETIME = Duration.ofDays(21);
  public static final String USER_ID = "Joe_the_User";
  public static final String USER_PASSWORD = "Joe's 4wesome PASSW0Rd";
  public static final String CLIENT_ID = "some_client_YAY-12334";
  public static final String CLIENT_SECRET = "and A secret FOR THAT client";

  Gson gson = new Gson();

  RequiredFunctions requiredFunctions;
  // private RequiredFunctions.AuthCodeGrantType authCodeRequiredFunctions;
  RequiredFunctions.PasswordGrantType passwordRequiredFunctions;
  RequiredFunctions.RefreshTokenGrantType refreshTokenRequiredFunctions;
  RequiredFunctions.TokenGeneration tokenGenerationRequiredFunctions;

  private OAuth2ServerConfiguration config;
  OAuth2ServerConfiguration.Builder configBuilder;

  boolean isGrantTypeAllowed;
  Optional<Client> client;
  Optional<User> user;

  Response actualResponse;

  public void init() {
    actualResponse = null;

    isGrantTypeAllowed = true;
    client = Optional.of(new Client());
    user = Optional.of(new User(USER_ID));

    requiredFunctions = new RequiredFunctions() {
      @Override
      public CompletableFuture<GetAccessTokenRes> getAccessToken(String bearerToken) {
        return CompletableFuture.completedFuture(new GetAccessTokenRes(new AccessToken(USER_ID)));
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
      public CompletableFuture<Void> saveAccessToken(String accessToken, String clientId, User user,
          Optional<LocalDateTime> expires) {
        Assert.assertEquals(ACCESS_TOKEN, accessToken);
        Assert.assertEquals(CLIENT_ID, clientId);
        Assert.assertEquals(new User(USER_ID), user);
        Assert.assertEquals(config.getAccessTokenLifetime()
                                  .isPresent(), expires.isPresent());

        if (config.getAccessTokenLifetime()
                  .isPresent()) {
          Assert.assertTrue(LocalDateTime.now()
                                         .plus(ACCESS_TOKEN_LIFETIME)
                                         .minusSeconds(1)
                                         .isBefore(expires.get()));
          Assert.assertTrue(LocalDateTime.now()
                                         .plus(ACCESS_TOKEN_LIFETIME)
                                         .plusSeconds(1)
                                         .isAfter(expires.get()));
        }
        return CompletableFuture.completedFuture(null);
      }
    };

    passwordRequiredFunctions = new RequiredFunctions.PasswordGrantType() {
      @Override
      public CompletableFuture<GetUserRes> getUser(String username, String password) {
        Assert.assertEquals(USER_ID, username);
        Assert.assertEquals(USER_PASSWORD, password);
        return CompletableFuture.completedFuture(new GetUserRes(user));
      }
    };

    refreshTokenRequiredFunctions = new RequiredFunctions.RefreshTokenGrantType() {
      @Override
      public CompletableFuture<Void> revokeRefreshToken(String refreshToken) {
        return CompletableFuture.completedFuture(null);
      }

      @Override
      public CompletableFuture<GetRefreshTokenRes> getRefreshToken(String refreshToken) {
        return CompletableFuture.completedFuture(new GetRefreshTokenRes(new RefreshToken(CLIENT_ID, USER_ID)));
      }

      @Override
      public CompletableFuture<Void> saveRefreshToken(String refreshToken, String clientId, User user,
          Optional<LocalDateTime> expires) {

        Assert.assertEquals(REFRESH_TOKEN, refreshToken);
        Assert.assertEquals(CLIENT_ID, clientId);
        Assert.assertEquals(new User(USER_ID), user);
        Assert.assertEquals(config.getRefreshTokenLifetime()
                                  .isPresent(), expires.isPresent());

        if (config.getRefreshTokenLifetime()
                  .isPresent()) {
          Assert.assertTrue(LocalDateTime.now()
                                         .plus(REFRESH_TOKEN_LIFETIME)
                                         .minusSeconds(1)
                                         .isBefore(expires.get()));
          Assert.assertTrue(LocalDateTime.now()
                                         .plus(REFRESH_TOKEN_LIFETIME)
                                         .plusSeconds(1)
                                         .isAfter(expires.get()));
        }
        return CompletableFuture.completedFuture(null);
      }
    };

    tokenGenerationRequiredFunctions = new RequiredFunctions.TokenGeneration() {
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

    configBuilder =
        new OAuth2ServerConfiguration.Builder(requiredFunctions).withPasswordGrantTypeSupport(passwordRequiredFunctions)
                                                                .withRefreshTokenGrantTypeSupport(
                                                                    refreshTokenRequiredFunctions)
                                                                .withTokenGenerationSupport(
                                                                    tokenGenerationRequiredFunctions)
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
