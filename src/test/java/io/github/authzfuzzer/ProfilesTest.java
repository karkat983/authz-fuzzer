package io.github.authzfuzzer;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

@SpringBootTest
class ProfilesTest {

    @Autowired
    Environment env;

    @Test
    void testsRunInTheTestProfile() {
        assertThat(env.getActiveProfiles()).containsExactly("test");
        assertThat(env.getProperty("spring.jpa.show-sql")).isEqualTo("false");
    }
}
