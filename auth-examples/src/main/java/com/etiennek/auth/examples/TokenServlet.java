package com.etiennek.auth.examples;

import java.io.IOException;
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
    AsyncContext context = req.startAsync();
    Reader reader = req.getReader();
    String body = CharStreams.toString(reader);
    server.grant(new Request("POST", header(req), body))
          .thenAccept((response) -> {
            resp.setStatus(response.getCode());
            context.complete();
          });
    // TODO: Should this be closed?
    reader.close();
  }

  private static ImmutableMap<String, String> header(HttpServletRequest req) {
    ImmutableMap.Builder<String, String> builder = new Builder<>();
    Enumeration<String> headerNames = req.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      builder.put(headerName, req.getHeader(headerName));
    }
    return builder.build();
  }
}
