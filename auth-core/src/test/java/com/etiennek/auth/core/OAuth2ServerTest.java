package com.etiennek.auth.core;

import static com.jayway.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.junit.Assert.assertEquals;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

import org.junit.Before;
import org.junit.Test;

import com.etiennek.auth.core.model.AccessToken;
import com.etiennek.auth.core.model.Client;
import com.etiennek.auth.core.model.RefreshToken;
import com.etiennek.auth.core.model.RequiredFunctions;
import com.etiennek.auth.core.model.TokenType;
import com.etiennek.auth.core.model.User;
import com.google.common.collect.ImmutableMap;

public class OAuth2ServerTest {

  private RequiredFunctions requiredFunctions;
  // private RequiredFunctions.AuthCodeGrantType authCodeRequiredFunctions;
  private RequiredFunctions.PasswordGrantType passwordRequiredFunctions;
  private RequiredFunctions.RefreshTokenGrantType refreshTokenRequiredFunctions;
  private RequiredFunctions.TokenGeneration tokenGenerationRequiredFunctions;

  private OAuth2ServerConfiguration config;
  private OAuth2Server oAuth2Server;

  private Response response0;

  @Before
  public void init() {
    response0 = null;
  }

  @Test
  public void Password_Grant_Type() throws Exception {

    LocalDateTime now = LocalDateTime.of(2014, 9, 5, 10, 23, 45, 930);
    LocalDateTime refreshTokenExpires = now.plusDays(14);

    String clientId = "Some_Client_ID_123";
    String clientSecret = "Some_Client_Secret_XXX_435";

    String userId = "Some_User_ID_BOB_438";
    String userPassword = "Some_user_PASSWORD_392";

    requiredFunctions = new RequiredFunctions() {

      @Override
      public CompletableFuture<GetAccessTokenRes> getAccessToken(String bearerToken) {
        CompletableFuture<GetAccessTokenRes> ret = new CompletableFuture<>();
        ret.complete(new GetAccessTokenRes(new AccessToken("AccessToken")));
        return ret;
      }

      @Override
      public CompletableFuture<GetClientRes> getClient(String clientId, String clientSecret) {
        CompletableFuture<GetClientRes> ret = new CompletableFuture<>();
        ret.complete(new GetClientRes(new Client(clientId)));
        return ret;
      }

      @Override
      public CompletableFuture<IsGrantTypeAllowedRes> isGrantTypeAllowed(String clientId, String grantType) {
        CompletableFuture<IsGrantTypeAllowedRes> ret = new CompletableFuture<>();
        ret.complete(new IsGrantTypeAllowedRes(true));
        return ret;
      }

      @Override
      public CompletableFuture<Void> saveAccessToken(String accessToken, String clientId, User user,
          LocalDateTime expires) {
        CompletableFuture<Void> ret = new CompletableFuture<>();
        ret.complete(null);
        return ret;
      }

    };

    passwordRequiredFunctions = new RequiredFunctions.PasswordGrantType() {
      @Override
      public CompletableFuture<GetUserRes> getUser(String username, String password) {
        CompletableFuture<GetUserRes> ret = new CompletableFuture<>();
        ret.complete(new GetUserRes(new User(userId)));
        return ret;
      }
    };

    refreshTokenRequiredFunctions = new RequiredFunctions.RefreshTokenGrantType() {
      @Override
      public CompletableFuture<Void> revokeRefreshToken(String refreshToken) {
        CompletableFuture<Void> ret = new CompletableFuture<>();
        ret.complete(null);
        return ret;
      }

      @Override
      public CompletableFuture<GetRefreshTokenRes> getRefreshToken(String refreshToken) {
        CompletableFuture<GetRefreshTokenRes> ret = new CompletableFuture<>();
        ret.complete(new GetRefreshTokenRes(new RefreshToken(clientId, userId, refreshTokenExpires)));
        return ret;
      }

      @Override
      public CompletableFuture<Void> saveRefreshToken(String refreshToken, String clientId, User user,
          LocalDateTime expires) {
        CompletableFuture<Void> ret = new CompletableFuture<>();
        ret.complete(null);
        return ret;
      }
    };

    tokenGenerationRequiredFunctions = new RequiredFunctions.TokenGeneration() {
      @Override
      public CompletableFuture<GenerateTokenRes> generateToken(TokenType tokenType) {
        CompletableFuture<GenerateTokenRes> ret = new CompletableFuture<>();

        new Thread("generateTokenThread") {
          public void run() {
            try {
              sleep(200);
            } catch (InterruptedException e) {
              e.printStackTrace();
            }
            if (tokenType == TokenType.ACCESS)
              ret.complete(new GenerateTokenRes("Access_Test_Token"));
            else
              ret.complete(new GenerateTokenRes("Refresh_Test_Token"));
          };
        }.start();

        return ret;
      }
    };

    config =
        new OAuth2ServerConfiguration.Builder(requiredFunctions).withPasswordGrantTypeSupport(passwordRequiredFunctions)
                                                                .withRefreshTokenGrantTypeSupport(
                                                                    refreshTokenRequiredFunctions)
                                                                .withTokenGenerationSupport(
                                                                    tokenGenerationRequiredFunctions)
                                                                .build();

    oAuth2Server = new OAuth2Server(config);

    ImmutableMap<String, String> reqHeader =
        ImmutableMap.of("Authorization", "Basic " + Base64.getEncoder()
                                                          .encodeToString((clientId + ":" + clientSecret).getBytes()),
            "Content-Type", "application/x-www-form-urlencoded");
    String reqBody = "grant_type=password&username=" + userId + "&password=" + userPassword;
    Request request = new Request("POST", reqHeader, reqBody);

    ImmutableMap<String, String> resHeader =
        ImmutableMap.of("Content-Type", "application/json;charset=UTF-8", "Cache-Control", "no-store", "Pragma",
            "no-cache");
    String resBody =
        "{\n\t\"access_token\":\"Access_Test_Token\",\n\t\"token_type\":\"bearer\",\n\t\"expires_in\":\"3600\",\n\t\"refresh_token\":\"Refresh_Test_Token\"\n}";

    oAuth2Server.grant(request)
                .whenComplete((response, e) -> {
                  response0 = response;
                });

    await().atMost(1000, MILLISECONDS)
           .until(() -> response0 != null);

    assertEquals(200, response0.getCode());
    assertEquals(resHeader, response0.getHeader());
    assertEquals(resBody, response0.getBody());
  }

}
