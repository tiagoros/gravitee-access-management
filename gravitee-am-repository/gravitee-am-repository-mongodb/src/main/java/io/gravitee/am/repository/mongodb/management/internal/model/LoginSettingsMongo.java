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
package io.gravitee.am.repository.mongodb.management.internal.model;

import io.gravitee.am.model.login.LoginSettings;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class LoginSettingsMongo {

    private boolean inherited;
    private boolean forgotPasswordEnabled;
    private boolean registerEnabled;
    private boolean rememberMeEnabled;
    private boolean passwordlessEnabled;
    private boolean hideForm;
    private boolean twoStepLoginEnabled;

    public boolean isInherited() {
        return inherited;
    }

    public void setInherited(boolean inherited) {
        this.inherited = inherited;
    }

    public boolean isForgotPasswordEnabled() {
        return forgotPasswordEnabled;
    }

    public void setForgotPasswordEnabled(boolean forgotPasswordEnabled) {
        this.forgotPasswordEnabled = forgotPasswordEnabled;
    }

    public boolean isRegisterEnabled() {
        return registerEnabled;
    }

    public void setRegisterEnabled(boolean registerEnabled) {
        this.registerEnabled = registerEnabled;
    }

    public boolean isRememberMeEnabled() {
        return rememberMeEnabled;
    }

    public void setRememberMeEnabled(boolean rememberMeEnabled) {
        this.rememberMeEnabled = rememberMeEnabled;
    }

    public boolean isPasswordlessEnabled() {
        return passwordlessEnabled;
    }

    public void setPasswordlessEnabled(boolean passwordlessEnabled) {
        this.passwordlessEnabled = passwordlessEnabled;
    }

    public boolean isHideForm() {
        return hideForm;
    }

    public void setHideForm(boolean hideForm) {
        this.hideForm = hideForm;
    }

    public boolean isTwoStepLoginEnabled() {
        return twoStepLoginEnabled;
    }

    public void setTwoStepLoginEnabled(boolean twoStepLoginEnabled) {
        this.twoStepLoginEnabled = twoStepLoginEnabled;
    }

    public LoginSettings convert() {
        LoginSettings loginSettings = new LoginSettings();
        loginSettings.setInherited(isInherited());
        loginSettings.setForgotPasswordEnabled(isForgotPasswordEnabled());
        loginSettings.setRegisterEnabled(isRegisterEnabled());
        loginSettings.setRememberMeEnabled(isRememberMeEnabled());
        loginSettings.setPasswordlessEnabled(isPasswordlessEnabled());
        loginSettings.setHideForm(!isTwoStepLoginEnabled() && isHideForm());
        loginSettings.setTwoStepLoginEnabled(isTwoStepLoginEnabled());

        return loginSettings;
    }

    public static LoginSettingsMongo convert(LoginSettings loginSettings) {
        if (loginSettings == null) {
            return null;
        }

        LoginSettingsMongo loginSettingsMongo = new LoginSettingsMongo();
        loginSettingsMongo.setInherited(loginSettings.isInherited());
        loginSettingsMongo.setForgotPasswordEnabled(loginSettings.isForgotPasswordEnabled());
        loginSettingsMongo.setRegisterEnabled(loginSettings.isRegisterEnabled());
        loginSettingsMongo.setRememberMeEnabled(loginSettings.isRememberMeEnabled());
        loginSettingsMongo.setPasswordlessEnabled(loginSettings.isPasswordlessEnabled());
        loginSettingsMongo.setHideForm(!loginSettings.isTwoStepLoginEnabled() && loginSettings.isHideForm());
        loginSettingsMongo.setTwoStepLoginEnabled(loginSettings.isTwoStepLoginEnabled());

        return loginSettingsMongo;
    }
}
