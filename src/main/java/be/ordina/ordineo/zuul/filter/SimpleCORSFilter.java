package be.ordina.ordineo.zuul.filter;

import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Component
public class SimpleCORSFilter implements Filter {

    private static final String[] allowOrigins = new String[]{"http://localhost:8080", "https://frontend-ordineo.cfapps.io"};

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) res;
        HttpServletRequest request = (HttpServletRequest) req;

        String originHeader = request.getHeader("Origin");

        if (Arrays.asList(allowOrigins).contains( originHeader )) {
            response.addHeader("Access-Control-Allow-Origin", originHeader);
            response.setHeader("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE, PATCH, HEAD, TRACE");
            response.setHeader("Access-Control-Max-Age", "3600");
            response.setHeader("Access-Control-Allow-Headers", "Origin, x-auth-token, Authorization, X-Requested-With, Content-Type, Accept");
            response.addHeader("Access-Control-Expose-Headers", "location");
            response.addHeader("Access-Control-Allow-Credentials", "true");
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }
}
