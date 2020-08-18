package com.sample;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class OIDCSampleFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse res = (HttpServletResponse) response;

        if (checkOAuth(req)) {
            chain.doFilter(request, response);
        } else {
            res.sendError(401);
        }
    }

    @Override
    public void destroy() {

    }

    private static boolean checkOAuth(final HttpServletRequest request) {

        final HttpSession currentSession = request.getSession(false);

        return currentSession != null
                && currentSession.getAttribute("authenticated") != null
                && (boolean) currentSession.getAttribute("authenticated");
    }
}
