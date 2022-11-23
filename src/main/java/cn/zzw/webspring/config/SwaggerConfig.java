package cn.zzw.webspring.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@EnableSwagger2
@Configuration
public class SwaggerConfig {
    @Bean
    public Docket customDocket() {
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("cn.zzw.webspring.controller"))
                .build();
    }

    private ApiInfo apiInfo() {
        Contact contact = new Contact("zecss", "http://www.zecss.cn", "my@my.com");
        return new ApiInfoBuilder()
                .title("接口文档")
                .description("")
                .contact(contact)   // 联系方式
                .version("1.1.0")  // 版本
                .build();
    }
}
