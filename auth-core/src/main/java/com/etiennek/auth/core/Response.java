package com.etiennek.auth.core;

import static com.etiennek.auth.core.Util.*;

import java.util.Map;

public class Response {
  private int code;
  private Map<String, String[]> header;
  private String body;

  public Response(int code, Map<String, String[]> header, String body) {
    super();
    this.code = code;
    this.header = checkNotNull(header);
    this.body = checkNotNull(body);
  }

  public int getCode() {
    return code;
  }

  public Map<String, String[]> getHeader() {
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
    Response other = (Response) obj;
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
    return "Response [code=" + code + ", header=" + header + ", body=" + body + "]";
  }

}
