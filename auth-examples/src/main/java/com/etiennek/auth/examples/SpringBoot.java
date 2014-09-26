package com.etiennek.auth.examples;

import javax.servlet.Servlet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.etiennek.auth.servlet.TokenServlet;

@Configuration
@EnableAutoConfiguration
public class SpringBoot {

  @Bean(name = "token")
  public Servlet dispatcherServlet() {
    return new TokenServlet(new ExampleServer());
  }

  public static void main(String[] args) throws Exception {
    SpringApplication.run(SpringBoot.class, args);
  }

}
