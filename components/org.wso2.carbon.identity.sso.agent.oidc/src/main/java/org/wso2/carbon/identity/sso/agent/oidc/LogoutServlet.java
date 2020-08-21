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

import org.apache.http.client.utils.URIBuilder;
import org.wso2.carbon.identity.sso.agent.oidc.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.oidc.util.SSOAgentConstants;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class LogoutServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        handleOIDCLogout(req, resp);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        handleOIDCLogout(req, resp);
    }

    private void handleOIDCLogout(HttpServletRequest req, HttpServletResponse resp)
            throws SSOAgentException, IOException {

        final HttpSession currentSession = req.getSession(false);
        final Properties properties = SSOAgentContextEventListener.getProperties();
        final String sessionState = (String) currentSession.getAttribute(SSOAgentConstants.SESSION_STATE);
        final String idToken = (String) currentSession.getAttribute("idToken");

        String logoutEP = properties.getProperty(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT);
        String redirectionURI = properties.getProperty(SSOAgentConstants.POST_LOGOUT_REDIRECTION_URI);

        URI uri;
        try {
            uri = new URIBuilder(logoutEP).addParameter("post_logout_redirect_uri", redirectionURI)
                    .addParameter("id_token_hint", idToken)
                    .addParameter("session_state", sessionState)
                    .build();
        } catch (URISyntaxException e) {
            throw new SSOAgentException("Error while fetching logout URL.", e);
        }
        resp.sendRedirect(uri.toString());
    }
}
