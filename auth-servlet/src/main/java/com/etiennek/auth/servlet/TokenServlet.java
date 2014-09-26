package com.etiennek.auth.servlet;

import java.io.IOException;

import javax.servlet.AsyncContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.etiennek.auth.core.FormRequest;
import com.etiennek.auth.core.OAuth2Server;

public class TokenServlet extends BaseServlet {
  private static final long serialVersionUID = 7569068162393846152L;

  public TokenServlet(OAuth2Server server) {
    super(server);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    AsyncContext context = req.startAsync();
    getServer().grant(new FormRequest(req.getMethod(), header(req), req.getParameterMap()))
               .thenAccept((response) -> handleResponse(response, resp, context));
  }

}
