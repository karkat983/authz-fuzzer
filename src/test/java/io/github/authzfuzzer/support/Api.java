package io.github.authzfuzzer.support;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;

import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import io.github.authzfuzzer.SeedData;

/**
 * Small helpers so tests read as "who does what to which resource". Shared by the example
 * tests and, later, the property suite.
 */
public final class Api {

    private final MockMvc mvc;

    public Api(MockMvc mvc) {
        this.mvc = mvc;
    }

    /** HTTP Basic credentials of a seeded user, e.g. as("bravo-admin"). */
    public static RequestPostProcessor as(String username) {
        return httpBasic(username, SeedData.PASSWORD);
    }

    public static String body(String name, String content) {
        return "{\"name\":\"" + name + "\",\"content\":\"" + content + "\"}";
    }

    public ResultActions list(String user) throws Exception {
        return send(MockMvcRequestBuilders.get("/api/resources"), user);
    }

    public ResultActions get(String user, long id) throws Exception {
        return send(MockMvcRequestBuilders.get("/api/resources/{id}", id), user);
    }

    public ResultActions create(String user, String name, String content) throws Exception {
        return send(json(MockMvcRequestBuilders.post("/api/resources"), name, content), user);
    }

    public ResultActions update(String user, long id, String name, String content) throws Exception {
        return send(json(MockMvcRequestBuilders.put("/api/resources/{id}", id), name, content), user);
    }

    public ResultActions delete(String user, long id) throws Exception {
        return send(MockMvcRequestBuilders.delete("/api/resources/{id}", id), user);
    }

    private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder b, String name, String content) {
        return b.contentType(MediaType.APPLICATION_JSON).content(body(name, content));
    }

    /** user == null sends the request without credentials. */
    private ResultActions send(MockHttpServletRequestBuilder request, String user) throws Exception {
        return mvc.perform(user == null ? request : request.with(as(user)));
    }
}
