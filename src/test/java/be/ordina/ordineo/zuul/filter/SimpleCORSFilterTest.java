/*package be.ordina.ordineo.zuul.filter;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.junit.Assert.*;

public class SimpleCORSFilterTest {

    SimpleCORSFilter filter;
    MockHttpServletResponse response ;
    MockHttpServletRequest request;
    MockFilterChain chain;

    @Before
    public void setup() {
        filter = new SimpleCORSFilter();

        response = new MockHttpServletResponse();
        request = new MockHttpServletRequest();
        chain = new MockFilterChain();
    }

    @Test
    public void init() throws ServletException {
        filter.init(null);
    }

    @Test
    public void destroy() {
        filter.destroy();
    }

    @Test
    public void headersShouldBeSetForLocal() throws IOException, ServletException {
        request.addHeader("Origin", "http://localhost:8080");

        filter.doFilter(request, response, chain);

        assertEquals("http://localhost:8080", response.getHeader("Access-Control-Allow-Origin"));
        assertEquals(1, response.getHeaderValues("Access-Control-Allow-Origin").size());
        assertEquals("3600", response.getHeader("Access-Control-Max-Age"));
        assertEquals("location", response.getHeader("Access-Control-Expose-Headers"));
        assertEquals("true", response.getHeader("Access-Control-Allow-Credentials"));

        for (RequestMethod requestMethod : RequestMethod.values()) {
            assertTrue("Should allow method " + requestMethod.name(), response.getHeader("Access-Control-Allow-Methods").contains(requestMethod.name()));
        }

        assertTrue("Should allow header Origin", response.getHeader("Access-Control-Allow-Headers").contains("Origin"));
        assertTrue("Should allow header X-Requested-With", response.getHeader("Access-Control-Allow-Headers").contains("X-Requested-With"));
        assertTrue("Should allow header Content-Type", response.getHeader("Access-Control-Allow-Headers").contains("Content-Type"));
        assertTrue("Should allow header Accept", response.getHeader("Access-Control-Allow-Headers").contains("Accept"));
    }

    @Test
    public void headersShouldBeSetForCloud() throws IOException, ServletException {
        request.addHeader("Origin", "https://frontend-ordineo.cfapps.io");

        filter.doFilter(request, response, chain);

        assertEquals("https://frontend-ordineo.cfapps.io", response.getHeader("Access-Control-Allow-Origin"));
        assertEquals(1, response.getHeaderValues("Access-Control-Allow-Origin").size());
        assertEquals("3600", response.getHeader("Access-Control-Max-Age"));
        assertEquals("location", response.getHeader("Access-Control-Expose-Headers"));
        assertEquals("true", response.getHeader("Access-Control-Allow-Credentials"));

        for (RequestMethod requestMethod : RequestMethod.values()) {
            assertTrue("Should allow method " + requestMethod.name(), response.getHeader("Access-Control-Allow-Methods").contains(requestMethod.name()));
        }

        assertTrue("Should allow header Origin", response.getHeader("Access-Control-Allow-Headers").contains("Origin"));
        assertTrue("Should allow header X-Requested-With", response.getHeader("Access-Control-Allow-Headers").contains("X-Requested-With"));
        assertTrue("Should allow header Content-Type", response.getHeader("Access-Control-Allow-Headers").contains("Content-Type"));
        assertTrue("Should allow header Accept", response.getHeader("Access-Control-Allow-Headers").contains("Accept"));
    }

    @Test
    public void headersShouldNotBeSetForOthers() throws IOException, ServletException {
        filter.doFilter(request, response, chain);

        assertNull(response.getHeader("Access-Control-Allow-Origin"));
        assertNull(response.getHeader("Access-Control-Max-Age"));
        assertNull(response.getHeader("Access-Control-Expose-Headers"));
        assertNull(response.getHeader("Access-Control-Allow-Methods"));
        assertNull(response.getHeader("Access-Control-Allow-Headers"));
        assertNull(response.getHeader("Access-Control-Allow-Credentials"));
    }

}
*/