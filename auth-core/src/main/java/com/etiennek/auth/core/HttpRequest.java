package com.etiennek.auth.core;

import java.util.Map;

import com.google.common.base.Preconditions;

public class HttpRequest {
  private String method;
  private Map<String, String> header;
  private String body;

  public HttpRequest(String method, Map<String, String> header, String body) {
    this.method = Preconditions.checkNotNull(method);
    this.header = Preconditions.checkNotNull(header);
    this.body = Preconditions.checkNotNull(body);
  }

  public String getMethod() {
    return method;
  }

  public Map<String, String> getHeader() {
    return header;
  }

  public String getBody() {
    return body;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((body == null) ? 0 : body.hashCode());
    result = prime * result + ((header == null) ? 0 : header.hashCode());
    result = prime * result + ((method == null) ? 0 : method.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    HttpRequest other = (HttpRequest) obj;
    if (body == null) {
      if (other.body != null)
        return false;
    } else if (!body.equals(other.body))
      return false;
    if (header == null) {
      if (other.header != null)
        return false;
    } else if (!header.equals(other.header))
      return false;
    if (method == null) {
      if (other.method != null)
        return false;
    } else if (!method.equals(other.method))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "HttpRequest [method=" + method + ", header=" + header + ", body=" + body + "]";
  }

}
