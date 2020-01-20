package com.test4.test4.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class AuthCheck extends HandlerInterceptorAdapter {

    @Override
    public void postHandle(HttpServletRequest request,
                           HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) throws Exception {

        response.setHeader("Content-type", "application/json;charset=UTF-8");



       // super.postHandle(request, response, handler, modelAndView);
    }

    @Override
    public void afterCompletion(HttpServletRequest request,
                                HttpServletResponse response, Object handler, Exception ex)
            throws Exception {
        super.afterCompletion(request, response, handler, ex);
    }

    @Override
    public boolean preHandle(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler) throws Exception {



        if(
                request.getRequestURL().toString().equals("http://localhost:8080/user/tryRegister") ||
                request.getRequestURL().toString().equals("http://localhost:8080/user/tryLogin") ||
                request.getRequestURL().toString().equals("http://localhost:8080/user/isAuthorized") ||
                request.getRequestURL().toString().equals("http://localhost:8080/user/logOut")

        )return true;

        System.out.println("request.getRequestURL().toString()");
        System.out.println(request.getRequestURL().toString());
        return IsAuthorized(request.getSession());



        // your code
    }
    public boolean IsAuthorized(HttpSession httpSession){

        if (httpSession.getAttribute("isAuthorized") == null) return true;
        return (boolean)httpSession.getAttribute("isAuthorized");
    }
}
