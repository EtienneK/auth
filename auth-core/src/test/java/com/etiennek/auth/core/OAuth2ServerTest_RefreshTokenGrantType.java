package com.etiennek.auth.core;

import static com.jayway.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.etiennek.auth.core.model.ErrorCode;
import com.etiennek.auth.core.model.RefreshToken;

public class OAuth2ServerTest_RefreshTokenGrantType extends TestBase {

  @Before
  public void init() {
    super.init();
  }

  @Test
  public void grant_SUCCESS_Refresh_Token_Grant_Type() throws Exception {
    // Arrange
    refreshToken = Optional.of(new RefreshToken(CLIENT_ID, USER_ID, now.plusNanos(1)));

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
    server().grant(newRefreshTokenGrantTypeRequest(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN))
            .whenComplete((response, e) -> {
              actualResponse = response;
            });

    await().atMost(1000, MILLISECONDS)
           .until(() -> actualResponse != null);

    // Assert
    assertResponse(expectedResponseCode, expectedResponseHeader, expectedResponseBody, actualResponse);
  }

  @Test
  public void grant_FAILURE_Refresh_Token_Grant_Type_Invalid_token() throws Exception {
    // Arrange
    refreshToken = Optional.empty();

    // Arrange - Expected Response
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("access_token", ACCESS_TOKEN);
    map.put("token_type", "bearer");
    map.put("expires_in", ACCESS_TOKEN_LIFETIME.getSeconds());
    map.put("refresh_token", REFRESH_TOKEN);

    int expectedResponseCode = 400;
    Map<String, String[]> expectedResponseHeader = urlFormEncodedResponseHeader();

    // Act
    server().grant(newRefreshTokenGrantTypeRequest(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN))
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

  @Test
  public void grant_FAILURE_Refresh_Token_Grant_Type_Invalid_token_Client_ID() throws Exception {
    // Arrange
    refreshToken = Optional.of(new RefreshToken(CLIENT_ID + "Another", USER_ID, now.plusDays(1)));

    // Arrange - Expected Response
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("access_token", ACCESS_TOKEN);
    map.put("token_type", "bearer");
    map.put("expires_in", ACCESS_TOKEN_LIFETIME.getSeconds());
    map.put("refresh_token", REFRESH_TOKEN);

    int expectedResponseCode = 400;
    Map<String, String[]> expectedResponseHeader = urlFormEncodedResponseHeader();

    // Act
    server().grant(newRefreshTokenGrantTypeRequest(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN))
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

  @Test
  public void grant_FAILURE_Refresh_Token_Grant_Type_expired() throws Exception {
    // Arrange
    refreshToken = Optional.of(new RefreshToken(CLIENT_ID, USER_ID, now.minusNanos(1)));

    // Arrange - Expected Response
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("access_token", ACCESS_TOKEN);
    map.put("token_type", "bearer");
    map.put("expires_in", ACCESS_TOKEN_LIFETIME.getSeconds());
    map.put("refresh_token", REFRESH_TOKEN);

    int expectedResponseCode = 400;
    Map<String, String[]> expectedResponseHeader = urlFormEncodedResponseHeader();

    // Act
    server().grant(newRefreshTokenGrantTypeRequest(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN))
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

  private FormRequest newRefreshTokenGrantTypeRequest(String clientId, String clientSecret, String token) {
    Map<String, String[]> requestHeader = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    requestHeader.put("Authorization",
        new String[] {"Basic " + Base64.getEncoder()
                                       .encodeToString((clientId + ":" + clientSecret).getBytes())});
    requestHeader.put("Content-Type", new String[] {"application/x-www-form-urlencoded"});

    Map<String, String[]> requestBody = new LinkedHashMap<>();
    requestBody.put("grant_type", new String[] {"refresh_token"});
    requestBody.put("refresh_token", new String[] {token});

    return new FormRequest("POST", requestHeader, requestBody);
  }

}
