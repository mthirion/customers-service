package org.acme.customer.rest;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.core.MediaType;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.hasItems;

@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CustomerResourceTest {

    @Test
    @Order(1)
    void get() {
        given()
                .when()
                .get("/customers")
                .then()
                .statusCode(200)
                .body("size()", equalTo(2))
                .body("firstName", hasItems("Eric","Saul") );
    }

    @Test
    @Order(2)
    void getById() {
        given()
                .when()
                .get("/customers/1")
                .then()
                .statusCode(200)
                .body("firstName", equalTo("Saul"))
                .body("lastName", equalTo("Goodman"));
    }

    @Test
    @Order(3)
    void create() {
        JsonObject jsonObject =
                Json.createObjectBuilder()
                        .add("firstName", "Testy")
                        .add("lastName", "Test")
                        .add("email", "testy@test.com")
                        .build();

        given()
                .contentType(MediaType.APPLICATION_JSON)
                .body(jsonObject.toString())
                .when()
                .post("/customers")
                .then()
                .statusCode(201);
    }

    @Test
    @Order(4)
    void updateById() {
        JsonObject jsonObject =
                Json.createObjectBuilder()
                        .add("email", "rick@test.com")
                        .add("phone", "00 00 00 00")
                        .build();

        given()
                .contentType(MediaType.APPLICATION_JSON)
                .body(jsonObject.toString())
                .when()
                .put("/customers/1")
                .then()
                .statusCode(204);
    }

    /*
    @Test
    @Order(5)
    void deleteById() {
        given()
                .when()
                .delete("/customers/1")
                .then()
                .statusCode(204);
    }*/
}