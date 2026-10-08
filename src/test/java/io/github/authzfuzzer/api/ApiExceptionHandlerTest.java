package io.github.authzfuzzer.api;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.github.authzfuzzer.service.NotFoundException;
import jakarta.validation.Valid;

class ApiExceptionHandlerTest {

    @RestController
    static class ThrowingController {

        @GetMapping("/missing/{id}")
        String missing(@PathVariable Long id) {
            throw new NotFoundException("resource of tenant bravo", id);
        }

        @PostMapping("/echo")
        String echo(@Valid @RequestBody ResourceRequest request) {
            return request.name();
        }
    }

    MockMvc mvc = MockMvcBuilders.standaloneSetup(new ThrowingController())
            .setControllerAdvice(new ApiExceptionHandler())
            .build();

    @Test
    void notFoundIsProblemJsonWithoutLeakingDetails() throws Exception {
        mvc.perform(get("/missing/42"))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.detail").value("Resource not found"))
                .andExpect(content().string(not(containsString("bravo"))))
                // "instance" echoes the caller's own request path; the detail must not add the ID.
                .andExpect(jsonPath("$.detail").value(not(containsString("42"))));
    }

    @Test
    void invalidBodyIs400ListingFields() throws Exception {
        mvc.perform(post("/echo").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"\",\"content\":\"x\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fields[0]").value("name"));
    }
}
