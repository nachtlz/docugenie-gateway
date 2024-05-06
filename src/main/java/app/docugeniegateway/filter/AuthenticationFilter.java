package app.docugeniegateway.filter;

import app.docugeniegateway.util.JwtUtil;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config>{

    @Autowired
    private RouteValidator validator;

//    @Autowired
//    private RestTemplate template;

    @Autowired
    private JwtUtil jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            if (validator.isSecured.test(exchange.getRequest())) {
                List<String> authHeadersList = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);

                if (authHeadersList == null || authHeadersList.isEmpty()) {
                    throw new RuntimeException("Missing authorization header");
                }

                String authHeader = authHeadersList.get(0);
                if (authHeader.startsWith("Bearer ")) {
                    String token = authHeader.substring(7);

                    try {
                        //template.getForObject("http://IDENTITY-SERVICE/validate?token=" + token, String.class);
                        jwtUtil.validateToken(token);
                    } catch (Exception e) {
                        throw new RuntimeException("Unauthorized access to application.");
                    }
                } else {
                    throw new RuntimeException("Invalid authorization header format");
                }
            }

            return chain.filter(exchange);
        };

    }

    public static class Config {

    }
}
