/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.agent.oidc;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.sso.agent.oidc.bean.TokenData;
import org.wso2.carbon.identity.sso.agent.oidc.exception.SSOAgentServerException;
import org.wso2.carbon.identity.sso.agent.oidc.util.CommonUtils;
import org.wso2.carbon.identity.sso.agent.oidc.util.SSOAgentConstants;

import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.wso2.carbon.identity.sso.agent.oidc.util.CommonUtils.getAppIdCookie;

/**
 * A servlet class to handle OIDC callback responses.
 */
public class OIDCCallbackResponseHandler extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        handleOIDCCallback(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        handleOIDCCallback(req, resp);
    }

    private void handleOIDCCallback(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException {

        Properties properties = SSOAgentContextEventListener.getProperties();
        String indexPage = getIndexPage(properties);

        // Error response from IDP
        if (isError(request)) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            handleAppIdCookieForLogout(request, response);
            response.sendRedirect(indexPage);
            return;
        }

        // Create the initial session
        if (request.getSession(false) == null) {
            request.getSession(true);
        }

        // Validate callback properties
        if (isLogout(request)) {
            CommonUtils.logout(request, response);
            response.sendRedirect(indexPage);
            return;
        }

        // Obtain and store session_state against this session
        request.getSession(false)
                .setAttribute(SSOAgentConstants.SESSION_STATE, request.getParameter(SSOAgentConstants.SESSION_STATE));

        if (isLogin(request)) {
            try {
                // Obtain token response
                getToken(request, response);
                response.sendRedirect("home.jsp");
            } catch (SSOAgentServerException e) {
                response.sendRedirect(indexPage);
            }
        }
    }

    private void handleAppIdCookieForLogout(HttpServletRequest request, HttpServletResponse response) {

        Optional<Cookie> appIdCookie = getAppIdCookie(request);

        if (appIdCookie.isPresent()) {
            CommonUtils.TOKEN_STORE.remove(appIdCookie.get().getValue());
            appIdCookie.get().setMaxAge(0);
            response.addCookie(appIdCookie.get());
        }
    }

    private String getIndexPage(Properties properties) {

        String indexPage = null;
        if (StringUtils.isNotBlank(properties.getProperty(SSOAgentConstants.INDEX_PAGE))) {
            indexPage = properties.getProperty(SSOAgentConstants.INDEX_PAGE);
        } else {
            indexPage = "./";
        }
        return indexPage;
    }

    private boolean isLogout(HttpServletRequest request) {

        if (request.getParameterMap().isEmpty()) {
            return true;
        }
        if (request.getParameterMap().containsKey("sp") &&
                request.getParameterMap().containsKey("tenantDomain")) {
            return true;
        }
        return false;
    }

    private Map<String, Object> getUserAttributes(String idToken) throws SSOAgentServerException {

        Map<String, Object> userClaimValueMap = new HashMap<>();
        try {
            JWTClaimsSet claimsSet = SignedJWT.parse(idToken).getJWTClaimsSet();
            Map<String, Object> customClaimValueMap = claimsSet.getClaims();

            for (String claim : customClaimValueMap.keySet()) {
                if (!SSOAgentConstants.OIDC_METADATA_CLAIMS.contains(claim)) {
                    userClaimValueMap.put(claim, customClaimValueMap.get(claim));
                }
            }
        } catch (ParseException e) {
            throw new SSOAgentServerException("Error while parsing JWT.");
        }
        return userClaimValueMap;
    }

    private void getToken(final HttpServletRequest request, final HttpServletResponse response)
            throws OAuthProblemException, OAuthSystemException, SSOAgentServerException {

        HttpSession session = request.getSession(false);
        if (!checkOAuth(request)) {
            session.invalidate();
            session = request.getSession();
        }
        final Optional<Cookie> appIdCookie = getAppIdCookie(request);
        final Properties properties = SSOAgentContextEventListener.getProperties();
        final TokenData storedTokenData;

        if (appIdCookie.isPresent()) {
            storedTokenData = TOKEN_STORE.get(appIdCookie.get().getValue());
            if (storedTokenData != null) {
                setTokenDataToSession(session, storedTokenData);
                return;
            }
        }

        final String authzCode = request.getParameter("code");

        if (authzCode == null) {
            throw new SSOAgentServerException("Authorization code not present in callback");
        }

        final OAuthClientRequest.TokenRequestBuilder oAuthTokenRequestBuilder =
                new OAuthClientRequest.TokenRequestBuilder(
                        properties.getProperty(SSOAgentConstants.OIDC_TOKEN_ENDPOINT));

        final OAuthClientRequest accessRequest = oAuthTokenRequestBuilder.setGrantType(GrantType.AUTHORIZATION_CODE)
                .setClientId(properties.getProperty(SSOAgentConstants.CONSUMER_KEY))
                .setClientSecret(properties.getProperty(SSOAgentConstants.CONSUMER_SECRET))
                .setRedirectURI(properties.getProperty(SSOAgentConstants.CALL_BACK_URL))
                .setCode(authzCode)
                .buildBodyMessage();

        //create OAuth client that uses custom http client under the hood
        final OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        final JSONObject requestObject = requestToJson(accessRequest);
        final OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);
        final JSONObject responseObject = responseToJson(oAuthResponse);
        final String accessToken = oAuthResponse.getParam("access_token");

        session.setAttribute("requestObject", requestObject);
        session.setAttribute("responseObject", responseObject);
        if (accessToken != null) {
            session.setAttribute("accessToken", accessToken);
            String idToken = oAuthResponse.getParam("id_token");
            if (idToken != null) {
                session.setAttribute("idToken", idToken);
            }
            session.setAttribute("authenticated", true);
            session.setAttribute("user", getUserAttributes(idToken));

            TokenData tokenData = new TokenData();
            tokenData.setAccessToken(accessToken);
            tokenData.setIdToken(idToken);

            final String sessionId = UUID.randomUUID().toString();
            TOKEN_STORE.put(sessionId, tokenData);
            final Cookie cookie = new Cookie("AppID", sessionId);
            cookie.setMaxAge(-1);
            cookie.setPath("/");
            response.addCookie(cookie);
        } else {
            session.invalidate();
        }
    }

    private boolean isLogin(HttpServletRequest request) {

        String authzCode = request.getParameter("code");
        return StringUtils.isNotBlank(authzCode);
    }

    private boolean isError(HttpServletRequest request) {

        String error = request.getParameter(SSOAgentConstants.ERROR);
        return StringUtils.isNotBlank(error);
    }
}
