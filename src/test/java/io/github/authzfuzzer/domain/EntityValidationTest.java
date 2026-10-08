package io.github.authzfuzzer.domain;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class EntityValidationTest {

    static ValidatorFactory factory;
    static Validator validator;

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    @Test
    void validEntitiesPass() {
        Tenant t = new Tenant("alpha");
        assertThat(validator.validate(t)).isEmpty();
        assertThat(validator.validate(new AppUser("alpha-admin", t, Role.ADMIN)))
                .isEmpty();
        assertThat(validator.validate(new Resource("doc", "text", t))).isEmpty();
    }

    @Test
    void tenantNameMustBeASlug() {
        assertThat(validator.validate(new Tenant("Alpha Corp"))).isNotEmpty();
        assertThat(validator.validate(new Tenant("a"))).isNotEmpty();
    }

    @Test
    void userNeedsUsernameAndRole() {
        Tenant t = new Tenant("alpha");
        assertThat(validator.validate(new AppUser("x", t, Role.VIEWER))).isNotEmpty();
        assertThat(validator.validate(new AppUser("alpha-viewer", t, null))).isNotEmpty();
    }

    @Test
    void resourceTextIsBounded() {
        Tenant t = new Tenant("alpha");
        assertThat(validator.validate(new Resource(" ", "text", t))).isNotEmpty();
        assertThat(validator.validate(new Resource("doc", "x".repeat(Resource.MAX_CONTENT + 1), t)))
                .isNotEmpty();
    }
}
