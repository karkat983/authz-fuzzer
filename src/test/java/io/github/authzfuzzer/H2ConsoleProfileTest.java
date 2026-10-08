package io.github.authzfuzzer;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

class H2ConsoleProfileTest {

    @Nested
    @SpringBootTest
    class DefaultProfile {

        @Autowired
        ApplicationContext context;

        @Test
        void consoleIsNotRegistered() {
            assertThat(context.containsBean("h2Console")).isFalse();
        }
    }

    @Nested
    @SpringBootTest
    @ActiveProfiles("dev")
    class DevProfile {

        @Autowired
        ApplicationContext context;

        @Test
        void consoleIsRegistered() {
            assertThat(context.containsBean("h2Console")).isTrue();
        }
    }
}
