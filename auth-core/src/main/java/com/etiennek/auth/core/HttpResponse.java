package com.etiennek.auth.core;

import java.util.Map;

import com.google.common.base.Preconditions;

public class HttpResponse {
  private int code;
  private Map<String, String> header;
  private String body;

  public HttpResponse(int code, Map<String, String> header, String body) {
    super();
    this.code = code;
    this.header = header;
    this.body = body;
  }

  public int getCode() {
    return code;
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
    result = prime * result + code;
    result = prime * result + ((header == null) ? 0 : header.hashCode());
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
    HttpResponse other = (HttpResponse) obj;
    if (body == null) {
      if (other.body != null)
        return false;
    } else if (!body.equals(other.body))
      return false;
    if (code != other.code)
      return false;
    if (header == null) {
      if (other.header != null)
        return false;
    } else if (!header.equals(other.header))
      return false;
    return true;
  }

  @Override
  public String toString() {
    return "HttpResponse [code=" + code + ", header=" + header + ", body=" + body + "]";
  }

}
