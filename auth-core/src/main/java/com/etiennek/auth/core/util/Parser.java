package com.etiennek.auth.core.util;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

public class Parser {

  public static ImmutableMap<String, ImmutableList<String>> splitQuery(String body) {
    try {
      Map<String, List<String>> queryPairs = new LinkedHashMap<>();
      String[] pairs = body.split("&");
      for (String pair : pairs) {
        int equalsIndex = pair.indexOf("=");
        String key = equalsIndex > 0 ? URLDecoder.decode(pair.substring(0, equalsIndex), "UTF-8") : pair;
        if (!queryPairs.containsKey(key)) {
          queryPairs.put(key, new LinkedList<String>());
        }
        String value =
            equalsIndex > 0 && pair.length() > equalsIndex + 1 ? URLDecoder.decode(pair.substring(equalsIndex + 1),
                "UTF-8") : null;
        queryPairs.get(key)
                  .add(value);
      }

      Map<String, ImmutableList<String>> toConvert = new LinkedHashMap<>(queryPairs.size());
      for (String key : queryPairs.keySet()) {
        toConvert.put(key, ImmutableList.copyOf(queryPairs.get(key)));
      }

      return ImmutableMap.copyOf(toConvert);
    } catch (UnsupportedEncodingException e) {
      // MUST never ever happen
      throw Throwables.propagate(e);
    }
  }
}
