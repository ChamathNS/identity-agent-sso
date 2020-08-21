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

package org.wso2.carbon.identity.sso.agent.oidc.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * This class holds the constants used in the module, sso-agent-oidc.
 */
public class SSOAgentConstants {

    // Oauth response parameters and session attributes
    public static final String ERROR = "error";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String SESSION_STATE = "session_state";

    // application specific request parameters and session attributes
    public static final String CONSUMER_KEY = "consumerKey";
    public static final String CONSUMER_SECRET = "consumerSecret";
    public static final String CALL_BACK_URL = "callBackUrl";
    public static final String SKIP_URIS = "skipURIs";
    public static final String INDEX_PAGE = "indexPage";
    public static final String SCOPE = "scope";
    public static final String OAUTH2_GRANT_TYPE = "grantType";
    public static final String OAUTH2_AUTHZ_ENDPOINT = "authorizeEndpoint";
    public static final String OIDC_LOGOUT_ENDPOINT = "logoutEndpoint";
    public static final String OIDC_SESSION_IFRAME_ENDPOINT = "sessionIFrameEndpoint";
    public static final String OIDC_TOKEN_ENDPOINT = "tokenEndpoint";
    public static final String POST_LOGOUT_REDIRECTION_URI = "postLogoutRedirectURI";

    // request headers
    public static final String REFERER = "referer";

    //context params
    public static final String APP_PROPERTY_FILE_PARAMETER_NAME = "app-property-file";
    public static final String JKS_PROPERTY_FILE_PARAMETER_NAME = "jks-property-file";

    //response types
    public static final String CODE = "code";
    public static final String TOKEN = "token";

    public static final Set<String> OIDC_METADATA_CLAIMS = new HashSet<>(
            Arrays.asList("at_hash", "sub", "iss", "aud", "nbf", "c_hash", "azp", "amr", "sid", "exp", "iat"));
}
