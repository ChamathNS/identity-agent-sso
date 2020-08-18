<%@ page import="org.apache.oltu.oauth2.client.request.OAuthClientRequest" %>
<%@ page import="org.apache.oltu.oauth2.common.exception.OAuthSystemException" %>
<%@ page import="org.wso2.carbon.identity.sso.agent.oidc.SSOAgentConstants" %>
<%@ page import="org.wso2.carbon.identity.sso.agent.oidc.SampleContextEventListener" %>
<%@ page import="java.util.Properties" %>
<%@ page contentType="text/html;charset=UTF-8" %>

<%
    Properties properties = SampleContextEventListener.getProperties();
    
    String consumerKey = properties.getProperty(SSOAgentConstants.CONSUMER_KEY);
    String authzEndpoint = properties.getProperty(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT);
    String authzGrantType = properties.getProperty(SSOAgentConstants.OAUTH2_GRANT_TYPE);
    String scope = properties.getProperty(SSOAgentConstants.SCOPE);
    String callBackUrl = properties.getProperty(SSOAgentConstants.CALL_BACK_URL);
    String logoutEndpoint = properties.getProperty(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT);
    String sessionIFrameEndpoint = properties.getProperty(SSOAgentConstants.OIDC_SESSION_IFRAME_ENDPOINT);
    
    session.setAttribute(SSOAgentConstants.OAUTH2_GRANT_TYPE, authzGrantType);
    session.setAttribute(SSOAgentConstants.CONSUMER_KEY, consumerKey);
    session.setAttribute(SSOAgentConstants.SCOPE, scope);
    session.setAttribute(SSOAgentConstants.CALL_BACK_URL, callBackUrl);
    session.setAttribute(SSOAgentConstants.OAUTH2_AUTHZ_ENDPOINT, authzEndpoint);
    session.setAttribute(SSOAgentConstants.OIDC_LOGOUT_ENDPOINT, logoutEndpoint);
    session.setAttribute(SSOAgentConstants.OIDC_SESSION_IFRAME_ENDPOINT, sessionIFrameEndpoint);
    
    OAuthClientRequest.AuthenticationRequestBuilder oAuthAuthenticationRequestBuilder =
            new OAuthClientRequest.AuthenticationRequestBuilder(authzEndpoint);
    oAuthAuthenticationRequestBuilder
            .setClientId(consumerKey)
            .setRedirectURI((String) session.getAttribute(SSOAgentConstants.CALL_BACK_URL))
            .setResponseType(authzGrantType)
            .setScope(scope);
    
    // Build the new response mode with form post.
    OAuthClientRequest authzRequest;
    try {
        authzRequest = oAuthAuthenticationRequestBuilder.buildQueryMessage();
        response.sendRedirect(authzRequest.getLocationUri());
        return;
    } catch (OAuthSystemException e) {
%>

<script type="text/javascript">
    window.location = "index.jsp";
</script>

<%
    }
%>
