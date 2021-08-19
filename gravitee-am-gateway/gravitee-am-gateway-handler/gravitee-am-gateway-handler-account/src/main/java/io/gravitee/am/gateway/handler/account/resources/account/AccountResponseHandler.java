/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.am.gateway.handler.account.resources.account;

import io.gravitee.am.common.factor.FactorDataKeys;
import io.gravitee.am.common.factor.FactorType;
import io.gravitee.am.factor.api.Enrollment;
import io.gravitee.am.gateway.handler.common.utils.ConstantKeys;
import io.gravitee.am.gateway.handler.root.resources.endpoint.mfa.FactorTypes;
import io.gravitee.am.model.Factor;
import io.gravitee.am.model.User;
import io.gravitee.am.model.factor.EnrolledFactor;
import io.gravitee.am.model.factor.EnrolledFactorChannel;
import io.gravitee.am.model.factor.EnrolledFactorSecurity;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.MediaType;
import io.gravitee.common.util.Maps;
import io.vertx.core.Handler;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.reactivex.core.http.HttpServerResponse;
import io.vertx.reactivex.ext.web.RoutingContext;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

import static io.gravitee.am.common.factor.FactorSecurityType.SHARED_SECRET;

public class AccountResponseHandler {

    public static void handleWIP(RoutingContext routingContext) {
        buildDefaultHeader(routingContext).end(getTemporaryWipResponseJson());
    }

    public static void handleDefaultResponse(RoutingContext routingContext, Object obj){
        buildDefaultHeader(routingContext).end(Json.encodePrettily(obj));
    }

    public static void handleGetProfileResponse(RoutingContext routingContext, User user){
        JsonObject userJson = JsonObject.mapFrom(user);
        userJson.remove("factors");
        buildDefaultHeader(routingContext).end(userJson.encodePrettily());
    }

    public static void handleUpdateUserResponse(RoutingContext routingContext) {
        buildDefaultHeader(routingContext).end(getUpdateUserResponseJson());
    }

    public static void handleUpdateUserResponse(RoutingContext routingContext, String message) {
        handleUpdateUserResponse(routingContext, message, 500);
    }

    public static void handleUpdateUserResponse(RoutingContext routingContext, String message, Integer statusCode) {
        buildDefaultHeader(routingContext).setStatusCode(statusCode).end(getUpdateUserResponseFailureJson(message));
    }

    private static HttpServerResponse buildDefaultHeader(RoutingContext routingContext) {
        return routingContext.response()
                .putHeader(HttpHeaders.CACHE_CONTROL, "no-store")
                .putHeader(HttpHeaders.PRAGMA, "no-cache")
                .putHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    }

    private static String getUpdateUserResponseFailureJson(String message) {
        return new JsonObject().put("status", "KO").put("errorMessage", message).toString();
    }

    private static String getUpdateUserResponseJson() {
        return new JsonObject().put("status", "OK").toString();
    }

    private static String getTemporaryWipResponseJson() {
        return new JsonObject().put("temp", "true").put("reason", "wip").toString();
    }

    public static void handleNoBodyResponse(RoutingContext routingContext) {
        routingContext.response().setStatusCode(204).end();
    }

    public static Handler<RoutingContext> handleEnrollNeedChallenge(RoutingContext routingContext, Factor factor, User user) {
        return routingContext1 -> {
            JsonObject enrollmentJson = new JsonObject();
            FactorType factorType = factor.getFactorType();
            switch (factor.getFactorType()) {
                case OTP:
                    AccountResponseHandler.handleUpdateUserResponse(routingContext,"Invalid MFA Enrollment State OTP factors do not need enrollment responses", 500);
                    break;
                case SMS:
                    AccountResponseHandler.handleDefaultResponse(routingContext,enrollmentJson.put("factorId", factor.getId()).put("account", new JsonObject().put("phoneNumber", routingContext.session().get(ConstantKeys.ENROLLED_FACTOR_PHONE_NUMBER))));
                    break;
                case EMAIL:
                    AccountResponseHandler.handleDefaultResponse(routingContext, enrollmentJson.put("factorId", factor.getId()).put("account", new JsonObject().put("email", routingContext.session().get(ConstantKeys.ENROLLED_FACTOR_EMAIL_ADDRESS))));
                    break;
                default:
                    AccountResponseHandler.handleUpdateUserResponse(routingContext,"Unexpected MFA type: " + factor.getFactorType(), 500);
                    throw new IllegalStateException("Unexpected MFA type: " + factor.getFactorType());
            }
        };
    }

    public static Handler<RoutingContext> handleEnrollNoChallenge(RoutingContext routingContext, Factor factor) {
        return routingContext1 -> AccountResponseHandler.handleDefaultResponse(routingContext, new JsonObject().put("factorId", factor.getId()));
    }
}
