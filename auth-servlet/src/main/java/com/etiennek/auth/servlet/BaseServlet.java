package com.etiennek.auth.servlet;

import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.AsyncContext;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.etiennek.auth.core.OAuth2Server;
import com.etiennek.auth.core.Response;

public abstract class BaseServlet extends HttpServlet {
  private static final long serialVersionUID = -1500041205026141751L;

  private final OAuth2Server server;

  public BaseServlet(OAuth2Server server) {
    this.server = server;
  }

  public OAuth2Server getServer() {
    return server;
  }

  void handleResponse(Response response, HttpServletResponse httpResponse, AsyncContext context) {
    try {
      setHeader(response, httpResponse);
      httpResponse.setStatus(response.getCode());
      httpResponse.getWriter()
                  .write(response.getBody());
    } catch (Exception e) {
      throw new RuntimeException(e);
    } finally {
      context.complete();
    }
  }

  static Map<String, String[]> header(HttpServletRequest req) {
    Map<String, String[]> ret = new LinkedHashMap<>();
    Enumeration<String> headerNames = req.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      ret.put(headerName.toLowerCase(), Collections.list(req.getHeaders(headerName))
                                                   .toArray(new String[0]));
    }
    return ret;
  }

  private static void setHeader(Response response, HttpServletResponse httpResponse) {
    for (String key : response.getHeader()
                              .keySet()) {
      String[] valueArr = response.getHeader()
                                  .get(key);
      if (valueArr != null && valueArr.length > 0) {
        httpResponse.setHeader(key, valueArr[0]);
      }
    }
  }
}
