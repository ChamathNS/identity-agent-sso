package com.sample;

import com.sample.claims.ClaimManagerProxy;

import java.io.IOException;
import java.util.Properties;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class SampleContextEventListener implements ServletContextListener {

    private static Properties properties;

    public void contextInitialized(ServletContextEvent servletContextEvent) {

        properties = new Properties();
        try {
            properties.load(servletContextEvent.getServletContext().
                    getResourceAsStream("/WEB-INF/classes/oidc-sample-app.properties"));
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Obtain a claim manager instance for this application and set it to servlet context
        ClaimManagerProxy claimManagerProxy =
                new ClaimManagerProxy(
                        properties.getProperty("claimManagementEndpoint"),
                        properties.getProperty("adminUsername"),
                        properties.getProperty("adminPassword"));

        servletContextEvent.getServletContext().setAttribute("claimManagerProxyInstance", claimManagerProxy);
    }

    public void contextDestroyed(ServletContextEvent servletContextEvent) {

    }

    /**
     * Get the properties of the sample
     *
     * @return Properties
     */
    public static Properties getProperties() {

        return properties;
    }

    public static String getPropertyByKey(final String key) {

        return properties.getProperty(key);
    }

}
