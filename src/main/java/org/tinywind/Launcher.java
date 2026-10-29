package org.tinywind;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author tinywind
 */
@SpringBootApplication
public class Launcher {

    private static final Log log = LogFactory.getLog(Launcher.class);

    public static void main(String[] args) {
        SpringApplication.run(Launcher.class, args);
    }
}
