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
import io.gravitee.am.common.jwt.JWT;
import io.gravitee.am.common.oidc.StandardClaims;
import io.gravitee.am.factor.api.FactorContext;
import io.gravitee.am.factor.api.FactorProvider;
import io.gravitee.am.factor.otp.utils.QRCode;
import io.gravitee.am.factor.utils.SharedSecret;
import io.gravitee.am.gateway.handler.account.resources.account.util.AccountRoutes;
import io.gravitee.am.gateway.handler.account.resources.account.util.ContextPathParamUtil;
import io.gravitee.am.gateway.handler.account.services.AccountManagementUserService;
import io.gravitee.am.gateway.handler.account.services.ActivityAuditService;
import io.gravitee.am.gateway.handler.common.user.UserService;
import io.gravitee.am.gateway.handler.common.utils.ConstantKeys;
import io.gravitee.am.gateway.handler.common.vertx.web.handler.RedirectHandler;
import io.gravitee.am.gateway.handler.manager.factor.FactorManager;
import io.gravitee.am.model.Domain;
import io.gravitee.am.model.Factor;
import io.gravitee.am.model.ReferenceType;
import io.gravitee.am.model.User;
import io.gravitee.am.model.common.Page;
import io.gravitee.am.model.factor.EnrolledFactor;
import io.gravitee.am.model.factor.EnrolledFactorChannel;
import io.gravitee.am.model.factor.EnrolledFactorSecurity;
import io.gravitee.am.model.factor.FactorStatus;
import io.gravitee.am.model.oidc.Client;
import io.gravitee.am.reporter.api.audit.AuditReportableCriteria;
import io.gravitee.am.reporter.api.audit.model.Audit;
import io.gravitee.am.service.FactorService;
import io.gravitee.common.util.Maps;
import io.reactivex.Maybe;
import io.reactivex.Single;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.reactivex.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

import static io.gravitee.am.common.factor.FactorSecurityType.SHARED_SECRET;

public class AccountEndpointHandler {
    private static final String FACTOR_ID_PATH_PARAM = "factorId";
    private final UserService userService;
    private final FactorService factorService;
    private final ActivityAuditService activityAuditService;
    private final AccountManagementUserService accountManagementUserService;
    private final FactorManager factorManager;
    private final ApplicationContext applicationContext;
    private final Domain domain;
    protected final Logger LOGGER = LoggerFactory.getLogger(getClass());

    public AccountEndpointHandler(UserService userService,
                                  FactorService factorService,
                                  ActivityAuditService activityAuditService,
                                  AccountManagementUserService accountManagementUserService,
                                  FactorManager factorManager,
                                  ApplicationContext applicationContext,
                                  Domain domain) {
        this.userService = userService;
        this.factorService = factorService;
        this.activityAuditService = activityAuditService;
        this.accountManagementUserService = accountManagementUserService;
        this.factorManager = factorManager;
        this.applicationContext = applicationContext;
        this.domain = domain;
    }

    //
    public void getAccount(RoutingContext routingContext) {
        //TODO: wip mounted angular
        User user = getUserFromContext(routingContext);
        AccountResponseHandler.handleWIP(routingContext);
    }

    //static assets
    public void getAsset(RoutingContext routingContext) {
        //TODO: wip static web assets
        User user = getUserFromContext(routingContext);
        AccountResponseHandler.handleWIP(routingContext);
    }

    public void getUserOrTimeout(RoutingContext routingContext) {
        JWT token = routingContext.get(ConstantKeys.TOKEN_CONTEXT_KEY);
        userService.findById(token.getSub()).doOnError(err -> {
            LOGGER.error("Unable to retrieve user for Id {}", token.getSub(), err);
        }).toSingle().subscribe(user -> {
            routingContext.put(ConstantKeys.USER_CONTEXT_KEY, user);
            routingContext.next();
        });
    }

    public void getProfile(RoutingContext routingContext) {
        AccountResponseHandler.handleGetProfileResponse(routingContext, routingContext.get(ConstantKeys.USER_CONTEXT_KEY));
    }

    public void getActivity(RoutingContext routingContext) {
        getActivityAudit(routingContext, routingContext.get(ConstantKeys.USER_CONTEXT_KEY))
                .subscribe(result -> AccountResponseHandler.handleDefaultResponse(routingContext, result));
    }

    public void redirectForgotPassword(RoutingContext routingContext) {
        final Client client = routingContext.get(ConstantKeys.CLIENT_CONTEXT_KEY);
        final String path = AccountRoutes.CHANGE_PASSWORD_REDIRECT.getRoute() + "?client_id=" + client.getClientId();
        RedirectHandler.create(path).handle(routingContext);
    }

    public void getUserFactors(RoutingContext routingContext) {
        collectFactors(routingContext.get(ConstantKeys.USER_CONTEXT_KEY))
                .subscribe(factors -> AccountResponseHandler.handleDefaultResponse(routingContext, factors));
    }

    public void updateProfile(RoutingContext routingContext) {
        User user = getUserFromContext(routingContext);
        User updatedUser = mapRequestToUser(user, routingContext);
        if (Objects.equals(user.getId(), updatedUser.getId())) {
            accountManagementUserService.update(user)
                    .doOnSuccess(nestedResult -> AccountResponseHandler.handleUpdateUserResponse(routingContext))
                    .doOnError(er -> AccountResponseHandler.handleUpdateUserResponse(routingContext, er.getMessage()))
                    .subscribe();
        } else {
            AccountResponseHandler.handleUpdateUserResponse(routingContext, "Mismatched user IDs", 401);
        }
    }

    public void enrollFactor(RoutingContext routingContext) {
        User user = getUserFromContext(routingContext);
        factorService.findById(getFactorIdFromBody(routingContext.getBodyAsJson())).subscribe(factor -> {
            FactorProvider factorProvider = factorManager.get(getFactorIdFromBody(routingContext.getBodyAsJson()));
            if (factorProvider.needChallengeSending()) {
                factorProvider.sendChallenge(new FactorContext(applicationContext, routingContext, new Maps.MapBuilder(new HashMap()).build()))
                        .doOnError(er -> AccountResponseHandler.handleUpdateUserResponse(routingContext, er.getMessage()))
                        .subscribe(() -> {
                            user.upsertFactor(buildEnrolledFactor(factor, routingContext, user, FactorStatus.PENDING_ACTIVATION));
                            updateUserFactor(routingContext, user, AccountResponseHandler.handleEnrollNeedChallenge(routingContext, factor, user));
                        });
            } else {
                factorProvider.enroll(user.getUsername()).subscribe(enrollment -> {
                    user.upsertFactor(buildEnrolledFactor(factor, routingContext, user, FactorStatus.PENDING_ACTIVATION));
                    updateUserFactor(routingContext, user, AccountResponseHandler.handleEnrollNoChallenge(routingContext, factor));
                });
            }
        });
    }

    public void handleFactorVerify(RoutingContext routingContext) {
        User user = getUserFromContext(routingContext);
        String factorId = getFactorIdFromPathParam(routingContext);
        String factorEnrollmentCode = getFactorEnrollmentCodeFromBody(routingContext);
        Maybe<Factor> factorMaybe = factorService.findById(factorId);
        factorMaybe.subscribe(factor -> {
            final FactorContext factorCtx = new FactorContext(applicationContext, routingContext, new Maps.MapBuilder(new HashMap())
                    .put(FactorContext.KEY_CODE, factorEnrollmentCode)
                    .put(FactorContext.KEY_ENROLLED_FACTOR, factor)
                    .build());
            factorManager.get(factor.getFactorType().getType()).verify(factorCtx)
                    .doOnError(er -> AccountResponseHandler.handleUpdateUserResponse(routingContext, er.getMessage()))
                    .subscribe(() -> {
                        EnrolledFactor enrolledFactor = buildEnrolledFactor(factor, routingContext, user, FactorStatus.ACTIVATED);
                        user.upsertFactor(enrolledFactor);
                        AccountResponseHandler.handleDefaultResponse(routingContext, enrolledFactor);
                    });
        });
    }

    public void removeFactorFromUser(RoutingContext routingContext) {
        User user = getUserFromContext(routingContext);
        user.removeFactorById(getFactorIdFromPathParam(routingContext));
        updateUserFactor(routingContext, user, AccountResponseHandler::handleNoBodyResponse);

        accountManagementUserService.update(user)
                .doOnSuccess(nestedResult -> AccountResponseHandler.handleNoBodyResponse(routingContext))
                .doOnError(er -> AccountResponseHandler.handleUpdateUserResponse(routingContext, er.getMessage()))
                .subscribe(res -> { /* no op */});
    }

    public void getUserEnrolledFactorById(RoutingContext routingContext) {
        User user = getUserFromContext(routingContext);
        String factorId = getFactorIdFromPathParam(routingContext);
        Optional<EnrolledFactor> factorMaybe = getEnrolledFactor(factorId, user);
        factorMaybe.ifPresentOrElse(factor -> AccountResponseHandler.handleDefaultResponse(routingContext, factor),
                () -> AccountResponseHandler.handleDefaultResponse(routingContext, null));
    }

    public void getSecurityDomainFactors(RoutingContext routingContext) {
        User user = getUserFromContext(routingContext);
        factorService.findByDomain(user.getReferenceId()).toList()
                .subscribe(factors -> AccountResponseHandler.handleDefaultResponse(routingContext, factors));
    }

    public void handleGetOtpQr(RoutingContext routingContext) {
        User user = getUserFromContext(routingContext);
        String factorId = getFactorIdFromBody(routingContext.getBodyAsJson());
        EnrolledFactor enrolledFactor = user.getFactors().stream().filter(factor -> Objects.equals(factorId, factor.getFactorId())).findFirst().get();
        if (Objects.equals(enrolledFactor.getSecurity().getType(), SHARED_SECRET)) {
            try {
                final String barCode = QRCode.generate(QRCode.generateURI(enrolledFactor.getSecurity().getValue(), "Gravitee.io", user.getUsername()), 200, 200);
                AccountResponseHandler.handleDefaultResponse(routingContext, new JsonObject().put("qrCode", barCode));
            } catch (Exception e) {
                routingContext.fail(401, e);
                e.printStackTrace();
            }
        }
    }

    private void updateUserFactor(RoutingContext routingContext, User user, final Handler<RoutingContext> requestHandler) {
        accountManagementUserService.update(user)
                .doOnError(er -> AccountResponseHandler.handleUpdateUserResponse(routingContext, er.getMessage()))
                .subscribe(res -> { requestHandler.handle(routingContext); });
    }

    private EnrolledFactor buildEnrolledFactor(Factor factor, RoutingContext routingContext, User user, FactorStatus factorStatus) {
        EnrolledFactor enrolledFactor = new EnrolledFactor();
        enrolledFactor.setFactorId(factor.getId());
        enrolledFactor.setStatus(factorStatus);
        switch (factor.getFactorType()) {
            case OTP:
                enrolledFactor.setSecurity(new EnrolledFactorSecurity(SHARED_SECRET, SharedSecret.generate()));
                break;
            case SMS:
                enrolledFactor.setChannel(new EnrolledFactorChannel(EnrolledFactorChannel.Type.SMS,
                        routingContext.session().get(ConstantKeys.ENROLLED_FACTOR_PHONE_NUMBER)));
                break;
            case EMAIL:
                Map<String, Object> additionalData = new Maps.MapBuilder(new HashMap())
                        .put(FactorDataKeys.KEY_MOVING_FACTOR, generateInitialMovingFactor(user))
                        .build();
                // For email even if the endUser will contains all relevant information, we extract only the Expiration Date of the code.
                // this is done only to enforce the other parameter (shared secret and initialMovingFactor)
                getEnrolledFactor(factor, user).ifPresent(ef -> {
                    additionalData.put(FactorDataKeys.KEY_EXPIRE_AT, ef.getSecurity().getData(FactorDataKeys.KEY_EXPIRE_AT, Long.class));
                });
                enrolledFactor.setSecurity(new EnrolledFactorSecurity(SHARED_SECRET,
                        routingContext.session().get(ConstantKeys.ENROLLED_FACTOR_SECURITY_VALUE_KEY),
                        additionalData));
                enrolledFactor.setChannel(new EnrolledFactorChannel(EnrolledFactorChannel.Type.EMAIL,
                        routingContext.session().get(ConstantKeys.ENROLLED_FACTOR_EMAIL_ADDRESS)));
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + factor.getFactorType().getType());
        }
        enrolledFactor.setCreatedAt(new Date());
        enrolledFactor.setUpdatedAt(enrolledFactor.getCreatedAt());
        return enrolledFactor;
    }

    private int generateInitialMovingFactor(User endUser) {
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(endUser.getUsername().getBytes(StandardCharsets.UTF_8));
            return secureRandom.nextInt(1000) + 1;
        } catch (NoSuchAlgorithmException e) {
            return 0;
        }
    }

    private Optional<EnrolledFactor> getEnrolledFactor(Factor factor, User endUser) {
        return endUser.getFactors()
                .stream()
                .filter(f -> factor.getId().equals(f.getFactorId()))
                .findFirst();
    }

    private Optional<EnrolledFactor> getEnrolledFactor(String factorId, User endUser) {
        return endUser.getFactors()
                .stream()
                .filter(f -> factorId.equals(f.getFactorId()))
                .findFirst();
    }

    private User mapRequestToUser(User user, RoutingContext routingContext) {
        JsonObject bodyAsJson = routingContext.getBodyAsJson();
        user.setFirstName(bodyAsJson.getString(StandardClaims.GIVEN_NAME));
        user.setLastName(bodyAsJson.getString(StandardClaims.FAMILY_NAME));
        user.setMiddleName(bodyAsJson.getString(StandardClaims.MIDDLE_NAME));
        user.setNickName(bodyAsJson.getString(StandardClaims.NICKNAME));
        user.setProfile(bodyAsJson.getString(StandardClaims.PROFILE));
        user.setPicture(bodyAsJson.getString(StandardClaims.PICTURE));
        user.setWebsite(bodyAsJson.getString(StandardClaims.WEBSITE));
        user.setEmail(bodyAsJson.getString(StandardClaims.EMAIL));
        user.setBirthdate(bodyAsJson.getString(StandardClaims.BIRTHDATE));
        user.setZoneInfo(bodyAsJson.getString(StandardClaims.ZONEINFO));
        user.setLocale(bodyAsJson.getString(StandardClaims.LOCALE));
        user.setPhoneNumber(bodyAsJson.getString(StandardClaims.PHONE_NUMBER));
        final JsonObject address = bodyAsJson.getJsonObject(StandardClaims.ADDRESS);
        if (address != null) {
            user.setAddress(convertClaim(address));
        }
        return user;
    }

    private Map<String, Object> convertClaim(JsonObject addressClaim) {
        Map<String, Object> address = new HashMap<>();
        address.put("street_address", addressClaim.getString("street_address"));
        address.put("locality", addressClaim.getString("locality"));
        address.put("region", addressClaim.getString("region"));
        address.put("postal_code", addressClaim.getString("postal_code"));
        address.put("country", addressClaim.getString("country"));
        return address;
    }

    private Single<Page<Audit>> getActivityAudit(RoutingContext routingContext, User user) {
        return activityAuditService.search(
                ReferenceType.DOMAIN,
                domain.getId(),
                new AuditReportableCriteria.Builder().user(user.getUsername()).build(),
                ContextPathParamUtil.getPageNumber(routingContext),
                ContextPathParamUtil.getPageSize(routingContext));
    }

    private Single<List<EnrolledFactor>> collectFactors(User user) {
        if (user.getFactors() == null) {
            return Single.just(Collections.emptyList());
        }
        return Single.just(user.getFactors());
    }

    private static String getFactorIdFromPathParam(RoutingContext routingContext) {
        return routingContext.pathParam(FACTOR_ID_PATH_PARAM);
    }

    private static String getFactorEnrollmentCodeFromBody(RoutingContext routingContext) {
        return routingContext.getBodyAsJson().getString("code");
    }

    private static User getUserFromContext(RoutingContext routingContext) {
        return routingContext.get(ConstantKeys.USER_CONTEXT_KEY);
    }

    private static String getFactorIdFromBody(JsonObject factorJson) {
        return factorJson.getString("factorId");
    }


}
