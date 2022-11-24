package cn.zzw.webspring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSpringApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebSpringApplication.class, args);
    }

}
