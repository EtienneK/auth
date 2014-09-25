package com.etiennek.auth.examples;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.AsyncContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.etiennek.auth.core.FormRequest;
import com.etiennek.auth.core.OAuth2Server;

public class TokenServlet extends HttpServlet {
  private static final long serialVersionUID = 7569068162393846152L;

  private OAuth2Server server;

  public TokenServlet(OAuth2Server server) {
    super();
    this.server = server;
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    AsyncContext context = req.startAsync();
    server.grant(new FormRequest(req.getMethod(), header(req), req.getParameterMap()))
          .thenAccept((response) -> {
            try {
              // TODO: headers
              resp.setStatus(response.getCode());
              resp.getWriter()
                  .write(response.getBody());
              context.complete();
            } catch (Exception e) {
              throw new RuntimeException(e);
            }
          });
  }

  private static Map<String, String[]> header(HttpServletRequest req) {
    Map<String, String[]> ret = new LinkedHashMap<>();
    Enumeration<String> headerNames = req.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      ret.put(headerName.toLowerCase(), Collections.list(req.getHeaders(headerName))
                                                   .toArray(new String[0]));
    }
    return ret;
  }
}
