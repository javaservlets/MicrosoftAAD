package com.example.azure;

import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.util.i18n.PreferredLocales;

import java.util.List;

@Node.Metadata(outcomeProvider = ActiveDirectory.MyOutcomeProvider.class, configClass = ActiveDirectory.Config.class)

public class ActiveDirectory implements Node {
    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "Azure";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    JsonValue context_json;

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        debug.error("+++     starting microsoft");

        context_json = context.sharedState.copy();
        String search_key = context_json.get("username").asString();

        UserInfo userinfo = new UserInfo(config.msTokenUrl(), config.msScope(), config.msAdmin(), config.msPassword(), config.msClientId(), config.msClientSecret());
        String status = userinfo.getStatus(config.msRiskUrl(), config.msUserUrl(), search_key); // qry could be for either "is" ENROLLED or COMPLIANT
        Action action = null ;

        debug.error("+++   action.process  " + status.toString());

        if (status.equals("high")) {
            action = goTo(MyOutcome.HIGH_RISK).build();
        } else if (status.equals("none")) {
            action = goTo(MyOutcome.NO_RISK).build();
        } else if (status.equals("unknown")) {
            action = goTo(MyOutcome.UNKNOWN).build();
        } else {
            action = goTo(MyOutcome.CONNECTION_ERROR).build();
        }
        return action;
    }


    public enum MyOutcome {
        /**
         * Successful parsing of cert for a dev id.
         */
        HIGH_RISK,
        /**
         * dev id found in cert but device isn't compliant
         */
        NO_RISK,
        /**
         * no device found with ID from cert
         */
        UNKNOWN,
        /**
         * no connection to mdm
         */
        CONNECTION_ERROR,
    }

    private Action.ActionBuilder goTo(MyOutcome outcome) {
        return Action.goTo(outcome.name());
    }

    public static class MyOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            return ImmutableList.of(
                    new Outcome(MyOutcome.NO_RISK.name(), "No Risk"),
                    new Outcome(MyOutcome.UNKNOWN.name(), "Unknown"),
                    new Outcome(MyOutcome.HIGH_RISK.name(), "High Risk"),
                    new Outcome(MyOutcome.CONNECTION_ERROR.name(), "Connection Error"));
        }
    }

    public interface Config {

        @Attribute(order = 100)
        default String msScope() {
            return "https://graph.microsoft.com/.default";
        }

        @Attribute(order = 200)
        default String msClientId() {
            return "";
        }

        @Attribute(order = 300)
        default String msClientSecret() {
            return "";
        }

        @Attribute(order = 400)
        default String msTokenUrl() {
            return "";
        }

        @Attribute(order = 500)
        default String msRiskUrl() {
            return "https://graph.microsoft.com/beta/riskyUsers/";
        }

        @Attribute(order = 501)
        default String msUserUrl() {
            return "https://graph.microsoft.com/v1.0/users/";
        }

        @Attribute(order = 600)
        default String msAdmin() {
            return "";
        }

        @Attribute(order = 700)
        default String msPassword() {
            return "";
        }

    }

    @Inject
    public ActiveDirectory(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

}