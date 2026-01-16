import {
  ActionGroup,
  Button,
  FormGroup,
  NumberInput,
  PageSection,
  Switch,
} from "@patternfly/react-core";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import { FormAccess } from "../../components/form/FormAccess";
import { HelpItem } from "@keycloak/keycloak-ui-shared";

type TokenSettingsTabProps = {
  realm: RealmRepresentation;
  save: (realm: RealmRepresentation) => void;
};

// Default values matching AAuthConfig.java
const DEFAULT_TOKEN_LIFESPAN = 300; // 5 minutes
const DEFAULT_REFRESH_LIFESPAN = 1800; // 30 minutes
const DEFAULT_EXCHANGE_MAX_DEPTH = 10;

export const TokenSettingsTab = ({ realm, save }: TokenSettingsTabProps) => {
  const { t } = useTranslation();
  const [tokenLifespan, setTokenLifespan] = useState(DEFAULT_TOKEN_LIFESPAN);
  const [refreshLifespan, setRefreshLifespan] = useState(DEFAULT_REFRESH_LIFESPAN);
  const [exchangeEnabled, setExchangeEnabled] = useState(true);
  const [exchangeMaxDepth, setExchangeMaxDepth] = useState(DEFAULT_EXCHANGE_MAX_DEPTH);

  useEffect(() => {
    // Parse token lifespan
    const tokenLifespanAttr = realm.attributes?.["aauth.token.lifespan"];
    if (tokenLifespanAttr) {
      const parsed = parseInt(tokenLifespanAttr, 10);
      setTokenLifespan(isNaN(parsed) ? DEFAULT_TOKEN_LIFESPAN : parsed);
    } else {
      setTokenLifespan(DEFAULT_TOKEN_LIFESPAN);
    }

    // Parse refresh lifespan
    const refreshLifespanAttr = realm.attributes?.["aauth.refresh.lifespan"];
    if (refreshLifespanAttr) {
      const parsed = parseInt(refreshLifespanAttr, 10);
      setRefreshLifespan(isNaN(parsed) ? DEFAULT_REFRESH_LIFESPAN : parsed);
    } else {
      setRefreshLifespan(DEFAULT_REFRESH_LIFESPAN);
    }

    // Parse exchange enabled
    const exchangeEnabledAttr = realm.attributes?.["aauth.exchange.enabled"];
    setExchangeEnabled(
      exchangeEnabledAttr === undefined || exchangeEnabledAttr === "true"
    );

    // Parse exchange max depth
    const exchangeMaxDepthAttr = realm.attributes?.["aauth.exchange.max.depth"];
    if (exchangeMaxDepthAttr) {
      const parsed = parseInt(exchangeMaxDepthAttr, 10);
      setExchangeMaxDepth(isNaN(parsed) ? DEFAULT_EXCHANGE_MAX_DEPTH : parsed);
    } else {
      setExchangeMaxDepth(DEFAULT_EXCHANGE_MAX_DEPTH);
    }
  }, [realm]);

  const handleSave = () => {
    const updatedRealm: RealmRepresentation = {
      ...realm,
      attributes: {
        ...realm.attributes,
        "aauth.token.lifespan": tokenLifespan.toString(),
        "aauth.refresh.lifespan": refreshLifespan.toString(),
        "aauth.exchange.enabled": exchangeEnabled.toString(),
        "aauth.exchange.max.depth": exchangeMaxDepth.toString(),
      },
    };
    save(updatedRealm);
  };

  const handleTokenLifespanChange = (
    event: React.FormEvent<HTMLInputElement>
  ) => {
    const newValue = Number(event.currentTarget.value);
    if (!isNaN(newValue)) {
      setTokenLifespan(Math.max(60, newValue));
    }
  };

  const handleRefreshLifespanChange = (
    event: React.FormEvent<HTMLInputElement>
  ) => {
    const newValue = Number(event.currentTarget.value);
    if (!isNaN(newValue)) {
      setRefreshLifespan(Math.max(60, newValue));
    }
  };

  const handleExchangeMaxDepthChange = (
    event: React.FormEvent<HTMLInputElement>
  ) => {
    const newValue = Number(event.currentTarget.value);
    if (!isNaN(newValue)) {
      setExchangeMaxDepth(Math.max(1, Math.min(100, newValue)));
    }
  };

  return (
    <PageSection variant="light">
      <FormAccess role="manage-realm" isHorizontal>
        <FormGroup
          label={t("authTokenLifespan")}
          fieldId="tokenLifespan"
          labelIcon={
            <HelpItem
              helpText={t("authTokenLifespanHelp")}
              fieldLabelId="authTokenLifespan"
            />
          }
        >
          <NumberInput
            id="tokenLifespan"
            value={tokenLifespan}
            min={60}
            max={86400}
            onMinus={() => setTokenLifespan(Math.max(60, tokenLifespan - 60))}
            onPlus={() => setTokenLifespan(Math.min(86400, tokenLifespan + 60))}
            onChange={handleTokenLifespanChange}
            inputName="tokenLifespan"
            inputAriaLabel={t("authTokenLifespan")}
            unit={t("seconds")}
          />
          <span className="pf-v5-u-ml-sm pf-v5-u-color-200">
            ({Math.floor(tokenLifespan / 60)} {t("minutes")})
          </span>
        </FormGroup>

        <FormGroup
          label={t("refreshTokenLifespan")}
          fieldId="refreshLifespan"
          labelIcon={
            <HelpItem
              helpText={t("refreshTokenLifespanHelp")}
              fieldLabelId="refreshTokenLifespan"
            />
          }
        >
          <NumberInput
            id="refreshLifespan"
            value={refreshLifespan}
            min={60}
            max={604800}
            onMinus={() => setRefreshLifespan(Math.max(60, refreshLifespan - 60))}
            onPlus={() =>
              setRefreshLifespan(Math.min(604800, refreshLifespan + 60))
            }
            onChange={handleRefreshLifespanChange}
            inputName="refreshLifespan"
            inputAriaLabel={t("refreshTokenLifespan")}
            unit={t("seconds")}
          />
          <span className="pf-v5-u-ml-sm pf-v5-u-color-200">
            ({Math.floor(refreshLifespan / 60)} {t("minutes")})
          </span>
        </FormGroup>

        <FormGroup
          label={t("enableTokenExchange")}
          fieldId="exchangeEnabled"
          hasNoPaddingTop
          labelIcon={
            <HelpItem
              helpText={t("enableTokenExchangeHelp")}
              fieldLabelId="enableTokenExchange"
            />
          }
        >
          <Switch
            id="exchangeEnabled"
            label={t("on")}
            labelOff={t("off")}
            isChecked={exchangeEnabled}
            onChange={(_, value) => setExchangeEnabled(value)}
            aria-label={t("enableTokenExchange")}
          />
        </FormGroup>

        {exchangeEnabled && (
          <FormGroup
            label={t("maxDelegationDepth")}
            fieldId="exchangeMaxDepth"
            labelIcon={
              <HelpItem
                helpText={t("maxDelegationDepthHelp")}
                fieldLabelId="maxDelegationDepth"
              />
            }
          >
            <NumberInput
              id="exchangeMaxDepth"
              value={exchangeMaxDepth}
              min={1}
              max={100}
              onMinus={() => setExchangeMaxDepth(Math.max(1, exchangeMaxDepth - 1))}
              onPlus={() =>
                setExchangeMaxDepth(Math.min(100, exchangeMaxDepth + 1))
              }
              onChange={handleExchangeMaxDepthChange}
              inputName="exchangeMaxDepth"
              inputAriaLabel={t("maxDelegationDepth")}
            />
          </FormGroup>
        )}

        <ActionGroup>
          <Button
            variant="primary"
            onClick={handleSave}
            data-testid="aauth-token-settings-save"
          >
            {t("save")}
          </Button>
        </ActionGroup>
      </FormAccess>
    </PageSection>
  );
};

