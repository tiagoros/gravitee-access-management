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
package io.gravitee.am.gateway.handler.account.resources.account.util;

import java.util.NoSuchElementException;

public enum FactorAction {
    ACTIVATE("activate"),
    VERIFY("verify"),
    CHALLENGE("challenge");

    FactorAction(String type) {
        this.type = type;
    }
    private final String type;

    public static FactorAction getFactorActionByType(String type){
        if (ACTIVATE.getType().equalsIgnoreCase(type)) return ACTIVATE;
        if (VERIFY.getType().equalsIgnoreCase(type)) return VERIFY;
        if (CHALLENGE.getType().equalsIgnoreCase(type)) return CHALLENGE;
        throw new NoSuchElementException(String.format("No factor action for provided type of %s", type));
    }

    public String getType() {
        return type;
    }
}
