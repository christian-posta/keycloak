import { Tab, TabTitleText, Tooltip } from "@patternfly/react-core";
import { useTranslation } from "react-i18next";
import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import {
  RoutableTabs,
  useRoutableTab,
} from "../../components/routable-tabs/RoutableTabs";
import { AAuthGeneralSettings } from "./AAuthGeneralSettings";
import { TrustedIssuersTab } from "./TrustedIssuersTab";
import { AgentPoliciesTab } from "./AgentPoliciesTab";
import { TokenSettingsTab } from "./TokenSettingsTab";
import { toAAuthTab, AAuthSubTab } from "../routes/AAuth";
import { useRealm } from "../../context/realm-context/RealmContext";

type AAuthTabProps = {
  realm: RealmRepresentation;
  save: (realm: RealmRepresentation) => void;
};

export const AAuthTab = ({ realm, save }: AAuthTabProps) => {
  const { t } = useTranslation();
  const { realm: realmName } = useRealm();

  const useAAuthTab = (tab: AAuthSubTab) =>
    useRoutableTab(toAAuthTab({ realm: realmName, tab }));

  const generalTab = useAAuthTab("general");
  const trustedIssuersTab = useAAuthTab("trusted-issuers");
  const agentPoliciesTab = useAAuthTab("agent-policies");
  const tokenSettingsTab = useAAuthTab("token-settings");

  return (
    <RoutableTabs
      mountOnEnter
      defaultLocation={toAAuthTab({
        realm: realmName,
        tab: "general",
      })}
    >
      <Tab
        id="general"
        data-testid="rs-aauth-general-tab"
        aria-label={t("aauthGeneralSubTab")}
        title={<TabTitleText>{t("general")}</TabTitleText>}
        tooltip={<Tooltip content={t("aauthGeneralHelpText")} />}
        {...generalTab}
      >
        <AAuthGeneralSettings realm={realm} save={save} />
      </Tab>
      <Tab
        id="trusted-issuers"
        data-testid="rs-aauth-trusted-issuers-tab"
        aria-label={t("trustedIssuersSubTab")}
        title={<TabTitleText>{t("trustedIssuers")}</TabTitleText>}
        tooltip={<Tooltip content={t("trustedIssuersHelpText")} />}
        {...trustedIssuersTab}
      >
        <TrustedIssuersTab realm={realm} save={save} />
      </Tab>
      <Tab
        id="agent-policies"
        data-testid="rs-aauth-agent-policies-tab"
        aria-label={t("agentPoliciesSubTab")}
        title={<TabTitleText>{t("agentPolicies")}</TabTitleText>}
        tooltip={<Tooltip content={t("agentPoliciesHelpText")} />}
        {...agentPoliciesTab}
      >
        <AgentPoliciesTab realm={realm} save={save} />
      </Tab>
      <Tab
        id="token-settings"
        data-testid="rs-aauth-token-settings-tab"
        aria-label={t("tokenSettingsSubTab")}
        title={<TabTitleText>{t("tokenSettings")}</TabTitleText>}
        tooltip={<Tooltip content={t("tokenSettingsHelpText")} />}
        {...tokenSettingsTab}
      >
        <TokenSettingsTab realm={realm} save={save} />
      </Tab>
    </RoutableTabs>
  );
};

export default AAuthTab;

