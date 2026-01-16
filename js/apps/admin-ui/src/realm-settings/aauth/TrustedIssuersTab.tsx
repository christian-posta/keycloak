import {
  ActionGroup,
  Button,
  FormGroup,
  PageSection,
  TextInput,
} from "@patternfly/react-core";
import { TrashIcon } from "@patternfly/react-icons";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import { FormAccess } from "../../components/form/FormAccess";
import { HelpItem } from "@keycloak/keycloak-ui-shared";
import { Table, Thead, Tr, Th, Tbody, Td } from "@patternfly/react-table";

type TrustedIssuersTabProps = {
  realm: RealmRepresentation;
  save: (realm: RealmRepresentation) => void;
};

export const TrustedIssuersTab = ({ realm, save }: TrustedIssuersTabProps) => {
  const { t } = useTranslation();
  const [trustedIssuers, setTrustedIssuers] = useState<string[]>([]);
  const [newIssuer, setNewIssuer] = useState("");

  useEffect(() => {
    const issuersAttr = realm.attributes?.["aauth.trusted.issuers"];
    if (issuersAttr) {
      try {
        const parsed = JSON.parse(issuersAttr);
        setTrustedIssuers(Array.isArray(parsed) ? parsed : []);
      } catch {
        setTrustedIssuers([]);
      }
    } else {
      setTrustedIssuers([]);
    }
  }, [realm]);

  const handleAddIssuer = () => {
    if (newIssuer && !trustedIssuers.includes(newIssuer)) {
      setTrustedIssuers([...trustedIssuers, newIssuer]);
      setNewIssuer("");
    }
  };

  const handleRemoveIssuer = (issuer: string) => {
    setTrustedIssuers(trustedIssuers.filter((i) => i !== issuer));
  };

  const handleSave = () => {
    const updatedRealm: RealmRepresentation = {
      ...realm,
      attributes: {
        ...realm.attributes,
        "aauth.trusted.issuers": JSON.stringify(trustedIssuers),
      },
    };
    save(updatedRealm);
  };

  return (
    <PageSection variant="light">
      <FormAccess role="manage-realm" isHorizontal>
        <FormGroup
          label={t("addTrustedIssuer")}
          fieldId="newIssuer"
          labelIcon={
            <HelpItem
              helpText={t("addTrustedIssuerHelp")}
              fieldLabelId="addTrustedIssuer"
            />
          }
        >
          <div style={{ display: "flex", gap: "8px" }}>
            <TextInput
              id="newIssuer"
              type="url"
              value={newIssuer}
              onChange={(_, value) => setNewIssuer(value)}
              placeholder="https://other-auth-server.example.com/realms/example"
              aria-label={t("trustedIssuerUrl")}
              style={{ flex: 1 }}
            />
            <Button
              variant="secondary"
              onClick={handleAddIssuer}
              isDisabled={!newIssuer}
            >
              {t("add")}
            </Button>
          </div>
        </FormGroup>

        <FormGroup
          label={t("trustedIssuers")}
          fieldId="trustedIssuersList"
          labelIcon={
            <HelpItem
              helpText={t("trustedIssuersListHelp")}
              fieldLabelId="trustedIssuers"
            />
          }
        >
          {trustedIssuers.length > 0 ? (
            <Table variant="compact" aria-label={t("trustedIssuers")}>
              <Thead>
                <Tr>
                  <Th>{t("issuerUrl")}</Th>
                  <Th>{t("actions")}</Th>
                </Tr>
              </Thead>
              <Tbody>
                {trustedIssuers.map((issuer) => (
                  <Tr key={issuer}>
                    <Td dataLabel={t("issuerUrl")}>{issuer}</Td>
                    <Td dataLabel={t("actions")}>
                      <Button
                        variant="plain"
                        onClick={() => handleRemoveIssuer(issuer)}
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
            <span className="pf-v5-u-color-200">{t("noTrustedIssuers")}</span>
          )}
        </FormGroup>

        <ActionGroup>
          <Button
            variant="primary"
            onClick={handleSave}
            data-testid="aauth-trusted-issuers-save"
          >
            {t("save")}
          </Button>
        </ActionGroup>
      </FormAccess>
    </PageSection>
  );
};

