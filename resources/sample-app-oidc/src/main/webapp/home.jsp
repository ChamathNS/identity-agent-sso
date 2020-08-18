<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<%--
  ~ Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@page import="com.nimbusds.jwt.ReadOnlyJWTClaimsSet" %>
<%@page import="com.nimbusds.jwt.SignedJWT" %>
<%@page import="com.sample.OAuth2Constants" %>
<%@page import="com.sample.SampleContextEventListener" %>
<%@page import="com.sample.claims.ClaimManagerProxy" %>
<%@page import="org.json.JSONObject" %>
<%@page import="java.util.ArrayList" %>
<%@page import="java.util.HashMap" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.Properties" %>

<%
    final HttpSession currentSession = request.getSession(false);
    
    if (currentSession == null || currentSession.getAttribute("authenticated") == null) {
        // A direct access to home. Must redirect to index
        response.sendRedirect("index.jsp");
        return;
    }
    
    final Properties properties = SampleContextEventListener.getProperties();
    final String sessionState = (String) currentSession.getAttribute(OAuth2Constants.SESSION_STATE);
    
    final JSONObject requestObject = (JSONObject) currentSession.getAttribute("requestObject");
    final JSONObject responseObject = (JSONObject) currentSession.getAttribute("responseObject");
    
    final String idToken = (String) currentSession.getAttribute("idToken");
    
    String name = "";
    
    Map<String, Object> customClaimValueMap = new HashMap<>();
    Map<String, String> oidcClaimDisplayValueMap = new HashMap();
    
    if (idToken != null) {
        try {
            name = SignedJWT.parse(idToken).getJWTClaimsSet().getSubject();
            ReadOnlyJWTClaimsSet claimsSet = SignedJWT.parse(idToken).getJWTClaimsSet();
            
            ClaimManagerProxy claimManagerProxy =
                    (ClaimManagerProxy) application.getAttribute("claimManagerProxyInstance");
            
            customClaimValueMap = claimsSet.getCustomClaims();
            
            oidcClaimDisplayValueMap =
                    claimManagerProxy.getOidcClaimDisplayNameMapping(new ArrayList<>(customClaimValueMap.keySet()));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
%>

<html>
<head>
    <title>Home</title>
    <style>
        html, body {
            height: 100%;
        }
        
        body {
            flex-direction: column;
            display: flex;
        }
        
        main {
            flex-shrink: 0;
        }
        
        main.center-segment {
            margin: auto;
            display: flex;
            align-items: center;
        }
        
        .element-padding {
            margin: auto;
            padding: 15px;
        }
        .center {
            margin-left: auto;
            margin-right: auto;
        }
    </style>
</head>
<body>
<main class="center-segment">
    <div style="text-align: center">
        <div class="element-padding">
            <h1>OIDC Sample App Home Page!</h1>
        </div>
        
        <div class="element-padding">
            <h1>Hi <%=name%></h1>
        </div>
        
        <% if (!oidcClaimDisplayValueMap.isEmpty()) { %>
        <div class="element-padding">
            <div class="element-padding">
                <h3 align="center">User Details</h3>
            </div>
            <table class="center">
                <tbody>
                <% for(String claim:oidcClaimDisplayValueMap.keySet()) { %>
                <tr>
                    <td><%=oidcClaimDisplayValueMap.get(claim)%></td>
                    <td><%=customClaimValueMap.get(claim).toString()%> </td>
                </tr>
                <% } %>
                </tbody>
            </table>
            <%  } else { %>
            <p align="center">No user details Available. Configure SP Claim Configurations.</p>
            <%  } %>
        </div>
        
        <div class="element-padding">
            <a href='<%=properties.getProperty("OIDC_LOGOUT_ENDPOINT")%>?post_logout_redirect_uri=<%=properties.getProperty("post_logout_redirect_uri")%>&id_token_hint=<%=idToken%>&session_state=<%=sessionState%>'>Logout</a>
        </div>
    </div>
</main>
</body>
</html>
