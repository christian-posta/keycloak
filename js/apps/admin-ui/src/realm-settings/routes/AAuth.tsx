import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type AAuthSubTab =
  | "general"
  | "trusted-issuers"
  | "agent-policies"
  | "token-settings";

export type AAuthTabParams = {
  realm: string;
  tab: AAuthSubTab;
};

const RealmSettingsSection = lazy(() => import("../RealmSettingsSection"));

export const AAuthRoute: AppRouteObject = {
  path: "/:realm/realm-settings/aauth/:tab",
  element: <RealmSettingsSection />,
  breadcrumb: (t) => t("aauth"),
  handle: {
    access: "view-realm",
  },
};

export const toAAuthTab = (params: AAuthTabParams): Partial<Path> => ({
  pathname: generateEncodedPath("/:realm/realm-settings/aauth/:tab", params),
});

