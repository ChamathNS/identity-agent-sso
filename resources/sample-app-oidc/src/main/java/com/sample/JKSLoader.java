package com.sample;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class JKSLoader implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        // First find jks properties
        final InputStream jksInputStream = this.getClass().getClassLoader().getResourceAsStream("jks.properties");

        if (jksInputStream == null) {
            return;
        }

        // Load properties
        final Properties jksProperties = new Properties();

        try {
            jksProperties.load(jksInputStream);
        } catch (IOException e) {
            return;
        }

        // Find and set JKS required for IS server communication
        final URL resource = this.getClass().getClassLoader().getResource(jksProperties.getProperty("keystorename"));

        if (resource != null) {
            System.setProperty("javax.net.ssl.trustStore", resource.getPath());
            System.setProperty("javax.net.ssl.trustStorePassword", jksProperties.getProperty("keystorepassword"));
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        // Ignored
    }

}
