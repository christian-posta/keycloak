import {
  ActionGroup,
  Button,
  FormGroup,
  PageSection,
  Radio,
  TextInput,
} from "@patternfly/react-core";
import { TrashIcon } from "@patternfly/react-icons";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import { FormAccess } from "../../components/form/FormAccess";
import { HelpItem } from "@keycloak/keycloak-ui-shared";
import { Table, Thead, Tr, Th, Tbody, Td } from "@patternfly/react-table";

type AgentPoliciesTabProps = {
  realm: RealmRepresentation;
  save: (realm: RealmRepresentation) => void;
};

type PolicyMode = "allow-all" | "allowlist" | "blocklist";

export const AgentPoliciesTab = ({ realm, save }: AgentPoliciesTabProps) => {
  const { t } = useTranslation();
  const [policyMode, setPolicyMode] = useState<PolicyMode>("allow-all");
  const [allowedAgents, setAllowedAgents] = useState<string[]>([]);
  const [blockedAgents, setBlockedAgents] = useState<string[]>([]);
  const [newAgent, setNewAgent] = useState("");
  const [allowedScopes, setAllowedScopes] = useState<string[]>([]);
  const [newScope, setNewScope] = useState("");

  useEffect(() => {
    // Parse allowed agents
    const allowedAttr = realm.attributes?.["aauth.allowed.agents"];
    if (allowedAttr) {
      try {
        const parsed = JSON.parse(allowedAttr);
        setAllowedAgents(Array.isArray(parsed) ? parsed : []);
      } catch {
        setAllowedAgents([]);
      }
    } else {
      setAllowedAgents([]);
    }

    // Parse blocked agents
    const blockedAttr = realm.attributes?.["aauth.blocked.agents"];
    if (blockedAttr) {
      try {
        const parsed = JSON.parse(blockedAttr);
        setBlockedAgents(Array.isArray(parsed) ? parsed : []);
      } catch {
        setBlockedAgents([]);
      }
    } else {
      setBlockedAgents([]);
    }

    // Parse allowed scopes
    const scopesAttr = realm.attributes?.["aauth.allowed.scopes"];
    if (scopesAttr) {
      try {
        const parsed = JSON.parse(scopesAttr);
        setAllowedScopes(Array.isArray(parsed) ? parsed : []);
      } catch {
        setAllowedScopes([]);
      }
    } else {
      setAllowedScopes([]);
    }

    // Determine policy mode
    if (allowedAttr && JSON.parse(allowedAttr).length > 0) {
      setPolicyMode("allowlist");
    } else if (blockedAttr && JSON.parse(blockedAttr).length > 0) {
      setPolicyMode("blocklist");
    } else {
      setPolicyMode("allow-all");
    }
  }, [realm]);

  const handleAddAgent = () => {
    if (!newAgent) return;

    if (policyMode === "allowlist" && !allowedAgents.includes(newAgent)) {
      setAllowedAgents([...allowedAgents, newAgent]);
    } else if (policyMode === "blocklist" && !blockedAgents.includes(newAgent)) {
      setBlockedAgents([...blockedAgents, newAgent]);
    }
    setNewAgent("");
  };

  const handleRemoveAgent = (agent: string) => {
    if (policyMode === "allowlist") {
      setAllowedAgents(allowedAgents.filter((a) => a !== agent));
    } else if (policyMode === "blocklist") {
      setBlockedAgents(blockedAgents.filter((a) => a !== agent));
    }
  };

  const handleAddScope = () => {
    if (newScope && !allowedScopes.includes(newScope)) {
      setAllowedScopes([...allowedScopes, newScope]);
      setNewScope("");
    }
  };

  const handleRemoveScope = (scope: string) => {
    setAllowedScopes(allowedScopes.filter((s) => s !== scope));
  };

  const handlePolicyModeChange = (mode: PolicyMode) => {
    setPolicyMode(mode);
    if (mode === "allow-all") {
      setAllowedAgents([]);
      setBlockedAgents([]);
    } else if (mode === "allowlist") {
      setBlockedAgents([]);
    } else if (mode === "blocklist") {
      setAllowedAgents([]);
    }
  };

  const handleSave = () => {
    const updatedRealm: RealmRepresentation = {
      ...realm,
      attributes: {
        ...realm.attributes,
        "aauth.allowed.agents": JSON.stringify(
          policyMode === "allowlist" ? allowedAgents : []
        ),
        "aauth.blocked.agents": JSON.stringify(
          policyMode === "blocklist" ? blockedAgents : []
        ),
        "aauth.allowed.scopes": JSON.stringify(allowedScopes),
      },
    };
    save(updatedRealm);
  };

  const currentAgentList =
    policyMode === "allowlist" ? allowedAgents : blockedAgents;

  return (
    <PageSection variant="light">
      <FormAccess role="manage-realm" isHorizontal>
        <FormGroup
          label={t("agentPolicyMode")}
          fieldId="agentPolicyMode"
          isStack
          hasNoPaddingTop
          labelIcon={
            <HelpItem
              helpText={t("agentPolicyModeHelp")}
              fieldLabelId="agentPolicyMode"
            />
          }
        >
          <Radio
            id="allow-all"
            name="policyMode"
            label={t("allowAllAgents")}
            isChecked={policyMode === "allow-all"}
            onChange={() => handlePolicyModeChange("allow-all")}
          />
          <Radio
            id="allowlist"
            name="policyMode"
            label={t("useAllowlist")}
            isChecked={policyMode === "allowlist"}
            onChange={() => handlePolicyModeChange("allowlist")}
          />
          <Radio
            id="blocklist"
            name="policyMode"
            label={t("useBlocklist")}
            isChecked={policyMode === "blocklist"}
            onChange={() => handlePolicyModeChange("blocklist")}
          />
        </FormGroup>

        {policyMode !== "allow-all" && (
          <>
            <FormGroup
              label={
                policyMode === "allowlist"
                  ? t("addAllowedAgent")
                  : t("addBlockedAgent")
              }
              fieldId="newAgent"
              labelIcon={
                <HelpItem
                  helpText={
                    policyMode === "allowlist"
                      ? t("addAllowedAgentHelp")
                      : t("addBlockedAgentHelp")
                  }
                  fieldLabelId="newAgent"
                />
              }
            >
              <div style={{ display: "flex", gap: "8px" }}>
                <TextInput
                  id="newAgent"
                  type="url"
                  value={newAgent}
                  onChange={(_, value) => setNewAgent(value)}
                  placeholder="https://agent.example.com"
                  aria-label={t("agentUrl")}
                  style={{ flex: 1 }}
                />
                <Button
                  variant="secondary"
                  onClick={handleAddAgent}
                  isDisabled={!newAgent}
                >
                  {t("add")}
                </Button>
              </div>
            </FormGroup>

            <FormGroup
              label={
                policyMode === "allowlist"
                  ? t("allowedAgents")
                  : t("blockedAgents")
              }
              fieldId="agentList"
              labelIcon={
                <HelpItem
                  helpText={
                    policyMode === "allowlist"
                      ? t("allowedAgentsHelp")
                      : t("blockedAgentsHelp")
                  }
                  fieldLabelId="agentList"
                />
              }
            >
              {currentAgentList.length > 0 ? (
                <Table
                  variant="compact"
                  aria-label={
                    policyMode === "allowlist"
                      ? t("allowedAgents")
                      : t("blockedAgents")
                  }
                >
                  <Thead>
                    <Tr>
                      <Th>{t("agentUrl")}</Th>
                      <Th>{t("actions")}</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {currentAgentList.map((agent) => (
                      <Tr key={agent}>
                        <Td dataLabel={t("agentUrl")}>{agent}</Td>
                        <Td dataLabel={t("actions")}>
                          <Button
                            variant="plain"
                            onClick={() => handleRemoveAgent(agent)}
                            aria-label={t("remove")}
                          >
                            <TrashIcon />
                          </Button>
                        </Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              ) : (
                <span className="pf-v5-u-color-200">
                  {policyMode === "allowlist"
                    ? t("noAllowedAgents")
                    : t("noBlockedAgents")}
                </span>
              )}
            </FormGroup>
          </>
        )}

        <FormGroup
          label={t("allowedScopes")}
          fieldId="allowedScopes"
          labelIcon={
            <HelpItem
              helpText={t("allowedScopesHelp")}
              fieldLabelId="allowedScopes"
            />
          }
        >
          <div style={{ display: "flex", gap: "8px", marginBottom: "8px" }}>
            <TextInput
              id="newScope"
              type="text"
              value={newScope}
              onChange={(_, value) => setNewScope(value)}
              placeholder="profile, email, data.read"
              aria-label={t("aauthScopeName")}
              style={{ flex: 1 }}
            />
            <Button
              variant="secondary"
              onClick={handleAddScope}
              isDisabled={!newScope}
            >
              {t("add")}
            </Button>
          </div>
          {allowedScopes.length > 0 ? (
            <Table variant="compact" aria-label={t("allowedScopes")}>
              <Thead>
                <Tr>
                  <Th>{t("aauthScopeName")}</Th>
                  <Th>{t("actions")}</Th>
                </Tr>
              </Thead>
              <Tbody>
                {allowedScopes.map((scope) => (
                  <Tr key={scope}>
                    <Td dataLabel={t("aauthScopeName")}>{scope}</Td>
                    <Td dataLabel={t("actions")}>
                      <Button
                        variant="plain"
                        onClick={() => handleRemoveScope(scope)}
                        aria-label={t("remove")}
                      >
                        <TrashIcon />
                      </Button>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          ) : (
            <span className="pf-v5-u-color-200">
              {t("noScopeRestrictions")}
            </span>
          )}
        </FormGroup>

        <ActionGroup>
          <Button
            variant="primary"
            onClick={handleSave}
            data-testid="aauth-agent-policies-save"
          >
            {t("save")}
          </Button>
        </ActionGroup>
      </FormAccess>
    </PageSection>
  );
};

