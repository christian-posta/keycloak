import {
  ActionGroup,
  Button,
  ClipboardCopy,
  FormGroup,
  PageSection,
  Switch,
} from "@patternfly/react-core";
import { useEffect } from "react";
import { FormProvider, useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import { FormAccess } from "../../components/form/FormAccess";
import { HelpItem } from "@keycloak/keycloak-ui-shared";
import { useAdminClient } from "../../admin-client";
import { useRealm } from "../../context/realm-context/RealmContext";

type AAuthGeneralSettingsProps = {
  realm: RealmRepresentation;
  save: (realm: RealmRepresentation) => void;
};

type FormFields = {
  aauthEnabled: boolean;
};

export const AAuthGeneralSettings = ({
  realm,
  save,
}: AAuthGeneralSettingsProps) => {
  const { t } = useTranslation();
  const { adminClient } = useAdminClient();
  const { realm: realmName } = useRealm();

  const form = useForm<FormFields>({
    defaultValues: {
      aauthEnabled:
        realm.attributes?.["aauth.enabled"] === "true" ||
        realm.attributes?.["aauth.enabled"] === undefined,
    },
  });

  const { handleSubmit, setValue, watch, reset } = form;

  useEffect(() => {
    reset({
      aauthEnabled:
        realm.attributes?.["aauth.enabled"] === "true" ||
        realm.attributes?.["aauth.enabled"] === undefined,
    });
  }, [realm, reset]);

  const onSubmit = async (data: FormFields) => {
    const updatedRealm: RealmRepresentation = {
      ...realm,
      attributes: {
        ...realm.attributes,
        "aauth.enabled": data.aauthEnabled.toString(),
      },
    };
    save(updatedRealm);
  };

  const aauthEnabled = watch("aauthEnabled");

  // Construct AAuth URLs
  const baseUrl = adminClient.baseUrl || "";
  const wellKnownUrl = `${baseUrl}/realms/${realmName}/.well-known/aauth-configuration`;
  const tokenEndpointUrl = `${baseUrl}/realms/${realmName}/protocol/aauth/token`;

  return (
    <PageSection variant="light">
      <FormProvider {...form}>
        <FormAccess
          role="manage-realm"
          isHorizontal
          onSubmit={handleSubmit(onSubmit)}
        >
          <FormGroup
            label={t("aauthEnabled")}
            fieldId="aauthEnabled"
            hasNoPaddingTop
            labelIcon={
              <HelpItem
                helpText={t("aauthEnabledHelp")}
                fieldLabelId="aauthEnabled"
              />
            }
          >
            <Switch
              id="aauthEnabled"
              label={t("on")}
              labelOff={t("off")}
              isChecked={aauthEnabled}
              onChange={(_, value) => setValue("aauthEnabled", value)}
              aria-label={t("aauthEnabled")}
            />
          </FormGroup>

          {aauthEnabled && (
            <>
              <FormGroup
                label={t("wellKnownEndpoint")}
                fieldId="wellKnownEndpoint"
                labelIcon={
                  <HelpItem
                    helpText={t("wellKnownEndpointHelp")}
                    fieldLabelId="wellKnownEndpoint"
                  />
                }
              >
                <ClipboardCopy isReadOnly>{wellKnownUrl}</ClipboardCopy>
              </FormGroup>

              <FormGroup
                label={t("tokenEndpoint")}
                fieldId="tokenEndpoint"
                labelIcon={
                  <HelpItem
                    helpText={t("tokenEndpointHelp")}
                    fieldLabelId="tokenEndpoint"
                  />
                }
              >
                <ClipboardCopy isReadOnly>{tokenEndpointUrl}</ClipboardCopy>
              </FormGroup>
            </>
          )}

          <ActionGroup>
            <Button
              variant="primary"
              type="submit"
              data-testid="aauth-general-save"
            >
              {t("save")}
            </Button>
          </ActionGroup>
        </FormAccess>
      </FormProvider>
    </PageSection>
  );
};

