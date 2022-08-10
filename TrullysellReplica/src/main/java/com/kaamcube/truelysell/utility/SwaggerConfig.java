//package com.kaamcube.truelysell.utility;
//
//import com.google.common.base.Predicate;
//import com.google.common.base.Predicates;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//import org.springframework.stereotype.Component;
//import org.springframework.web.servlet.config.annotation.EnableWebMvc;
//import springfox.documentation.builders.ApiInfoBuilder;
//import springfox.documentation.builders.PathSelectors;
//import springfox.documentation.builders.RequestHandlerSelectors;
//import springfox.documentation.service.ApiInfo;
//import springfox.documentation.spi.DocumentationType;
//import springfox.documentation.spring.web.plugins.Docket;
//import springfox.documentation.swagger2.annotations.EnableSwagger2;
//
//import static com.google.common.base.Predicates.or;
//import static springfox.documentation.builders.PathSelectors.regex;
//
//@EnableWebMvc
//@EnableSwagger2
//@Component
//public class SwaggerConfig {
//
//	private Predicate<String> postPaths() {
//		return or(regex("*/*"), regex("*/*"));
//	}
//	@Bean
//	public Docket postsApi() {
//
//		return new Docket(DocumentationType.SWAGGER_2).groupName("TruelySell").apiInfo(apiInfo()).select()
//				.apis(Predicates.not(RequestHandlerSelectors.basePackage("com.kaamcube.truelysell.controller")))
//				.paths(PathSelectors.any()).build().pathMapping("/");
////	.paths(PathSelectors.any()).build();
//
//	}
//
//	private ApiInfo apiInfo() {
//
//		return new ApiInfoBuilder().title("TruelySell API")
//
//				.description("Kaamcube TruelySell API Documentation Generateed Using SWAGGER2 for our Course Rest API")
//
//				.termsOfServiceUrl("https://www.youtube.com/channel/UC-85Tmx8lhNZQmBNbxZiqkw")
//
//				.license("wuele8 Rest API License")
//
//				.licenseUrl("https://www.youtube.com/channel/UC-85Tmx8lhNZQmBNbxZiqkw").version("1.0").build();
//
//	}
//
//}
