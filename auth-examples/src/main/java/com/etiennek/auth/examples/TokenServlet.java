package com.etiennek.auth.examples;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Enumeration;
import java.util.logging.Logger;

import javax.servlet.AsyncContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.etiennek.auth.core.OAuth2Server;
import com.etiennek.auth.core.Request;
import com.google.common.base.Charsets;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMap.Builder;
import com.google.common.io.CharStreams;

public class TokenServlet extends HttpServlet {
  private static final long serialVersionUID = 7569068162393846152L;

  private OAuth2Server server;

  public TokenServlet(OAuth2Server server) {
    super();
    this.server = server;
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    String body = CharStreams.toString(new InputStreamReader(req.getInputStream(), Charsets.UTF_8));
    AsyncContext context = req.startAsync();
    server.grant(new Request("POST", header(req), body))
          .thenAccept((response) -> {
            try {
              resp.setStatus(response.getCode());
              resp.getWriter()
                  .write(response.getBody());
              context.complete();
            } catch (Exception e) {
              throw Throwables.propagate(e);
            }
          });
  }

  private static ImmutableMap<String, String> header(HttpServletRequest req) {
    ImmutableMap.Builder<String, String> builder = new Builder<>();
    Enumeration<String> headerNames = req.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      builder.put(headerName.toLowerCase(), req.getHeader(headerName));
    }
    return builder.build();
  }
}
