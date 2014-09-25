package com.etiennek.auth.core;

import static org.junit.Assert.assertEquals;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;

import org.junit.Assert;

import com.etiennek.auth.core.model.Client;
import com.etiennek.auth.core.model.RefreshToken;
import com.etiennek.auth.core.model.RequiredFunctions;
import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.model.User;
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

  Map<String, String[]> jsonResponseHeader() {
    Map<String, String[]> ret = new LinkedHashMap<>();
    ret.put("Content-Type", new String[] {"application/json;charset=UTF-8"});
    ret.put("Cache-Control", new String[] {"no-store"});
    ret.put("Pragma", new String[] {"no-cache"});
    return ret;
  }

  Map<String, String[]> urlFormEncodedResponseHeader() {
    return urlFormEncodedResponseHeader(null);
  }

  Map<String, String[]> urlFormEncodedResponseHeader(Map<String, String[]> extraHeaders) {
    Map<String, String[]> ret = new LinkedHashMap<>();
    if (extraHeaders == null)
      extraHeaders = new LinkedHashMap<>();
    ret.put("Content-Type", new String[] {"application/x-www-form-urlencoded"});
    ret.put("Cache-Control", new String[] {"no-store"});
    ret.put("Pragma", new String[] {"no-cache"});
    ret.putAll(extraHeaders);

    return ret;
  }

  static void assertResponse(int expectedResponseCode, Map<String, String[]> expectedResponseHeader,
      String expectedResponseBody, Response actualResponse) {
    assertEquals(expectedResponseCode, actualResponse.getCode());
    if (expectedResponseHeader != null)
      mapWithArrayValueEquals(expectedResponseHeader, actualResponse.getHeader());
    if (expectedResponseBody != null)
      assertEquals(expectedResponseBody, actualResponse.getBody());
  }

  private static void mapWithArrayValueEquals(Map<String, String[]> expected, Map<String, String[]> actual) {
    assertEquals(expected.keySet(), actual.keySet());
    for (String key : expected.keySet()) {
      String[] expectedArr = expected.get(key);
      String[] actualArr = actual.get(key);
      Assert.assertEquals("Key '" + key + "' length must be equal.", expectedArr.length, actualArr.length);
      for (int i = 0; i < expectedArr.length; i++) {
        Assert.assertEquals("Values for Key '" + key + "' do not match.", expectedArr[i], actualArr[i]);
      }
    }
  }

  FormRequest newPasswordGrantTypeRequest(String clientId, String clientSecret, String userId, String userPassword) {
    Map<String, String[]> requestHeader = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    requestHeader.put("Authorization",
        new String[] {"Basic " + Base64.getEncoder()
                                       .encodeToString((clientId + ":" + clientSecret).getBytes())});
    requestHeader.put("Content-Type", new String[] {"application/x-www-form-urlencoded"});

    Map<String, String[]> requestBody = new LinkedHashMap<>();
    requestBody.put("grant_type", new String[] {"password"});
    requestBody.put("username", new String[] {userId});
    requestBody.put("password", new String[] {userPassword});

    return new FormRequest("POST", requestHeader, requestBody);
  }

}
