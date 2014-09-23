package com.etiennek.auth.core;

import static com.etiennek.auth.core.Const.MEDIA_X_WWW_FORM_URLENCODED;
import static com.jayway.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.etiennek.auth.core.model.ErrorCode;
import com.google.common.collect.ImmutableMap;

public class OAuth2ServerTest_PasswordGrantType extends TestBase {

  @Before
  public void init() {
    super.init();
  }

  @Test
  public void grant_SUCCESS_Password_Grant_Type() throws Exception {
    // Arrange - Expected Response
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("access_token", ACCESS_TOKEN);
    map.put("token_type", "bearer");
    map.put("expires_in", ACCESS_TOKEN_LIFETIME.getSeconds());
    map.put("refresh_token", REFRESH_TOKEN);

    int expectedResponseCode = 200;
    Map<String, String> expectedResponseHeader = jsonResponseHeader();
    String expectedResponseBody = gson.toJson(map);

    // Act
    server().grant(newPasswordGrantTypeRequest(CLIENT_ID, CLIENT_SECRET, USER_ID, USER_PASSWORD))
            .whenComplete((response, e) -> {
              actualResponse = response;
            });

    await().atMost(1000, MILLISECONDS)
           .until(() -> actualResponse != null);

    // Assert
    assertResponse(expectedResponseCode, expectedResponseHeader, expectedResponseBody, actualResponse);
  }

  @Test
  public void grant_FAILURE_Password_Grant_Type_invalid_userame_or_password() throws Exception {
    // Arrange
    user = Optional.empty();

    // Arrange - Request
    ImmutableMap<String, String> requestHeader =
        imbs().put("Authorization", "Basic " + Base64.getEncoder()
                                                     .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()))
              .put("Content-Type", MEDIA_X_WWW_FORM_URLENCODED)
              .build();
    String requestBody = "grant_type=password&username=" + encode(USER_ID) + "&password=" + encode(USER_PASSWORD);
    Request request = new Request("POST", requestHeader, requestBody);

    // Arrange - Expected Response
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("access_token", ACCESS_TOKEN);
    map.put("token_type", "bearer");

    int expectedResponseCode = 400;
    Map<String, String> expectedResponseHeader = urlFormEncodedResponseHeader();

    // Act
    server().grant(request)
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
  public void grant_FAILURE_Password_Grant_Type_missing_userame() throws Exception {
    // Arrange - Request
    ImmutableMap<String, String> requestHeader =
        imbs().put("Authorization", "Basic " + Base64.getEncoder()
                                                     .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()))
              .put("Content-Type", MEDIA_X_WWW_FORM_URLENCODED)
              .build();
    String requestBody = "grant_type=password&password=" + encode(USER_PASSWORD);
    Request request = new Request("POST", requestHeader, requestBody);

    // Arrange - Expected Response
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("access_token", ACCESS_TOKEN);
    map.put("token_type", "bearer");

    int expectedResponseCode = 401;
    ImmutableMap<String, String> expectedResponseHeader =
        urlFormEncodedResponseHeader(imbs().put("WWW-Authenticate", "Basic realm=\"Service\"")
                                           .build());

    // Act
    server().grant(request)
            .whenComplete((response, e) -> {
              actualResponse = response;
            });

    await().atMost(1000, MILLISECONDS)
           .until(() -> actualResponse != null);

    // Assert
    assertResponse(expectedResponseCode, expectedResponseHeader, null, actualResponse);
    Assert.assertTrue(actualResponse.getBody()
                                    .contains("error=" + ErrorCode.INVALID_CLIENT + "&"));
  }

  @Test
  public void grant_FAILURE_Password_Grant_Type_missing_password() throws Exception {
    // Arrange - Request
    ImmutableMap<String, String> requestHeader =
        imbs().put("Authorization", "Basic " + Base64.getEncoder()
                                                     .encodeToString((CLIENT_ID + ":" + CLIENT_SECRET).getBytes()))
              .put("Content-Type", MEDIA_X_WWW_FORM_URLENCODED)
              .build();
    String requestBody = "grant_type=password&username=" + encode(USER_ID);
    Request request = new Request("POST", requestHeader, requestBody);

    // Arrange - Expected Response
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("access_token", ACCESS_TOKEN);
    map.put("token_type", "bearer");

    int expectedResponseCode = 401;
    ImmutableMap<String, String> expectedResponseHeader =
        urlFormEncodedResponseHeader(imbs().put("WWW-Authenticate", "Basic realm=\"Service\"")
                                           .build());

    // Act
    server().grant(request)
            .whenComplete((response, e) -> {
              actualResponse = response;
            });

    await().atMost(1000, MILLISECONDS)
           .until(() -> actualResponse != null);

    // Assert
    assertResponse(expectedResponseCode, expectedResponseHeader, null, actualResponse);
    Assert.assertTrue(actualResponse.getBody()
                                    .contains("error=" + ErrorCode.INVALID_CLIENT + "&"));
  }

}
