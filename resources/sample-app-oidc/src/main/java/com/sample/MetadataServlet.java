package com.sample;

import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Optional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MetadataServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
            throws IOException {

        final Optional<Cookie> appIdCookie = CommonUtils.getAppIdCookie(req);

        if (appIdCookie.isPresent()) {
            metadataResponse(appIdCookie.get(), resp);
        } else {
            sendNotFound(resp);
        }
    }

    private static void sendNotFound(final HttpServletResponse response) throws IOException {

        response.sendError(404);
    }

    private static void metadataResponse(final Cookie appIdCookie, final HttpServletResponse response) throws IOException {

        final Optional<TokenData> tokenData = CommonUtils.getTokenDataByCookieID(appIdCookie.getValue());

        if (tokenData.isPresent()) {
            final JSONObject jsonObject = new JSONObject();
            jsonObject.put("AccessToken", tokenData.get().getAccessToken());
            jsonObject.put("ApiEndpoint", SampleContextEventListener.getPropertyByKey("api_endpoint"));

            final PrintWriter responseWriter = response.getWriter();
            responseWriter.write(jsonObject.toString());

            response.setHeader("Content-Type", "application/json");

            responseWriter.close();

        } else {
            sendNotFound(response);
        }
    }

}
