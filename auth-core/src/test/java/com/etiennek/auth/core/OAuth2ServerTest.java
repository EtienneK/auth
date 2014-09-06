package com.etiennek.auth.core;

import static org.junit.Assert.*;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import com.etiennek.auth.core.model.*;

public class OAuth2ServerTest {

  private RequiredFunctions requiredFunctions;
  // private RequiredFunctions.AuthCodeGrantType authCodeRequiredFunctions;
  private RequiredFunctions.PasswordGrantType passwordRequiredFunctions;
  private RequiredFunctions.RefreshTokenGrantType refreshTokenRequiredFunctions;
  private RequiredFunctions.TokenGeneration tokenGenerationRequiredFunctions;

  private OAuth2ServerConfiguration config;
  private OAuth2Server oAuth2Server;

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
      public CompletableFuture<IsGrantTypeAllowedRes> isGrantTypeAllowed(String clientId,
          GrantType grantType) {
        CompletableFuture<IsGrantTypeAllowedRes> ret = new CompletableFuture<>();
        ret.complete(new IsGrantTypeAllowedRes(true));
        return ret;
      }

      @Override
      public CompletableFuture<Void> saveAccessToken(String accessToken, String clientId,
          User user, LocalDateTime expires) {
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
      public CompletableFuture<Void> saveRefreshToken(String refreshToken, String clientId,
          User user, LocalDateTime expires) {
        CompletableFuture<Void> ret = new CompletableFuture<>();
        ret.complete(null);
        return ret;
      }
    };

    tokenGenerationRequiredFunctions = new RequiredFunctions.TokenGeneration() {
      @Override
      public CompletableFuture<GenerateTokenRes> generateToken(TokenType tokenType) {
        if (tokenType == TokenType.ACCESS)
          return CompletableFuture.completedFuture(new GenerateTokenRes("Access_Test_Token"));
        return CompletableFuture.completedFuture(new GenerateTokenRes("Refresh_Test_Token"));
      }
    };

    config =
        OAuth2ServerConfiguration.builder(requiredFunctions)
            .withPasswordGrantTypeSupport(passwordRequiredFunctions)
            .withRefreshTokenGrantTypeSupport(refreshTokenRequiredFunctions)
            .withTokenGenerationSupport(tokenGenerationRequiredFunctions).build();

    oAuth2Server = new OAuth2Server(config);

    Map<String, String> reqHeader = new HashMap<>();
    reqHeader.put("Authorization",
        "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()));
    reqHeader.put("Content-Type", "application/x-www-form-urlencoded");
    String reqBody = "grant_type=password&username=" + userId + "&password=" + userPassword;
    HttpRequest request = new HttpRequest("POST", reqHeader, reqBody);

    Map<String, String> resHeader = new HashMap<>();
    resHeader.put("Content-Type", "application/json;charset=UTF-8");
    resHeader.put("Cache-Control", "no-store");
    resHeader.put("Pragma", "no-cache");
    String resBody =
        "{\n\t\"access_token\":\"Access_Test_Token\",\n\t\"token_type\":\"bearer\",\n\t\"expires_in\":\"3600\",\n\t\"refresh_token\":\"Refresh_Test_Token\"\n}";

    assertEquals(new HttpResponse(200, resHeader, resBody),
        oAuth2Server.grant(request).get(2, TimeUnit.SECONDS));
  }

}
