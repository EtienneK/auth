package com.etiennek.auth.core;

import static com.jayway.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.etiennek.auth.core.model.ErrorCode;
import com.etiennek.auth.core.model.RequiredFunctions;

public class OAuth2ServerTest_ClientCredentialsGrantType extends TestBase {

  @Before
  public void init() {
    super.init();
  }

  @Test
  public void grant_SUCCESS_Client_Credentials_Grant_Type() throws Exception {
    // Arrange - Server
    configBuilder.withClientCredentialsGrantTypeSupport(new RequiredFunctions.ClientCredentialsGrantType() {
      @Override
      public CompletableFuture<GetUserFromClientRes> getUserFromClient(String clientId, String clientSecret) {
        Assert.assertEquals(CLIENT_ID, clientId);
        Assert.assertEquals(CLIENT_SECRET, clientSecret);
        return CompletableFuture.completedFuture(new GetUserFromClientRes(user));
      }
    });

    // Arrange - Expected Response
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("access_token", ACCESS_TOKEN);
    map.put("token_type", "bearer");
    map.put("expires_in", ACCESS_TOKEN_LIFETIME.getSeconds());
    map.put("refresh_token", REFRESH_TOKEN);

    int expectedResponseCode = 200;
    Map<String, String[]> expectedResponseHeader = jsonResponseHeader();
    String expectedResponseBody = gson.toJson(map);

    // Act
    server().grant(newClientCredentialsGrantTypeRequest(CLIENT_ID, CLIENT_SECRET))
            .whenComplete((response, e) -> {
              actualResponse = response;
            });

    await().atMost(1000, MILLISECONDS)
           .until(() -> actualResponse != null);

    // Assert
    assertResponse(expectedResponseCode, expectedResponseHeader, expectedResponseBody, actualResponse);
  }

  @Test
  public void grant_FAILURE_Client_Credentials_Grant_Type_cant_find_user() throws Exception {
    // Arrange - Server
    configBuilder.withClientCredentialsGrantTypeSupport(new RequiredFunctions.ClientCredentialsGrantType() {
      @Override
      public CompletableFuture<GetUserFromClientRes> getUserFromClient(String clientId, String clientSecret) {
        return CompletableFuture.completedFuture(new GetUserFromClientRes(Optional.empty()));
      }
    });

    // Arrange - Expected Response
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("access_token", ACCESS_TOKEN);
    map.put("token_type", "bearer");
    map.put("expires_in", ACCESS_TOKEN_LIFETIME.getSeconds());
    map.put("refresh_token", REFRESH_TOKEN);

    int expectedResponseCode = 400;
    Map<String, String[]> expectedResponseHeader = urlFormEncodedResponseHeader();

    // Act
    server().grant(newClientCredentialsGrantTypeRequest(CLIENT_ID, CLIENT_SECRET))
            .whenComplete((response, e) -> {
              actualResponse = response;
            });

    await().atMost(1000, MILLISECONDS)
           .until(() -> actualResponse != null);

    // Assert
    assertResponse(expectedResponseCode, expectedResponseHeader, null, actualResponse);
    Assert.assertTrue(actualResponse.getBody()
                                    .contains("error=" + ErrorCode.INVALID_GRANT + "&"));
  }

  private FormRequest newClientCredentialsGrantTypeRequest(String clientId, String clientSecret) {
    Map<String, String[]> requestHeader = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    requestHeader.put("Authorization",
        new String[] {"Basic " + Base64.getEncoder()
                                       .encodeToString((clientId + ":" + clientSecret).getBytes())});
    requestHeader.put("Content-Type", new String[] {"application/x-www-form-urlencoded"});

    Map<String, String[]> requestBody = new LinkedHashMap<>();
    requestBody.put("grant_type", new String[] {"client_credentials"});

    return new FormRequest("POST", requestHeader, requestBody);
  }

}
