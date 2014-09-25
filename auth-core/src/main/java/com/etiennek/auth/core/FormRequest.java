package com.etiennek.auth.core;

import static com.etiennek.auth.core.Util.*;

import java.util.Map;

public class FormRequest {
  private String method;
  private Map<String, String[]> header;
  private Map<String, String[]> body;

  public FormRequest(String method, Map<String, String[]> header, Map<String, String[]> body) {
    this.method = checkNotNull(method);
    this.body = checkNotNull(body);
    this.header = toCaseInsensitiveMap(header);
  }

  public String getMethod() {
    return method;
  }

  public Map<String, String[]> getHeader() {
    return header;
  }

  public Map<String, String[]> getBody() {
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
    FormRequest other = (FormRequest) obj;
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
    return "FormRequest [method=" + method + ", header=" + header + ", body=" + body + "]";
  }
}
