package br.com.microservice.stateful_any_api.infra;

import br.com.microservice.stateful_any_api.core.client.TokenClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.invoker.HttpClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

@Configuration
public class HttpInterfaceConfig {

    @Value("${app.client.base-url}")
    private String baseUrl;

    @Bean
    public TokenClient tokenClient(){
        return HttpServiceProxyFactory.builderFor(WebClientAdapter.create(WebClient.create(baseUrl))).build().createClient(TokenClient.class);
    }
}
