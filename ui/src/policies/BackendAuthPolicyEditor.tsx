import { useState } from "react";
import {
  ArrowLeftRight,
  Cloud,
  Github,
  KeyRound,
  ShieldCheck,
  Users,
} from "lucide-react";
import {
  EnumSelector,
  type EnumSelectorOption,
} from "../components/EnumSelector";
import {
  SchemaYamlEditor,
  parseSchemaYamlEditorValue,
} from "../components/SchemaYamlEditor";
import { Field, FieldGroup, StatusBanner } from "../components/Primitives";
import type { SchemaHelp } from "../schemaHelp";
import type { BackendAuth } from "../gateway-config";
import { cleanEmpty, hostPortError, toYamlText } from "./policyUtils";
import { ResultingYaml } from "./ResultingYaml";

type AuthKind =
  | "passthrough"
  | "key"
  | "gcp"
  | "aws"
  | "azure"
  | "copilot"
  | "oauth"
  | "crossAppAccess";

const authKindOptions: Array<EnumSelectorOption<AuthKind>> = [
  {
    value: "passthrough",
    label: "Passthrough",
    description: "Forward the validated incoming JWT to the backend.",
    icon: <ShieldCheck size={16} />,
  },
  {
    value: "key",
    label: "Static key",
    description: "Send a fixed secret value to the backend.",
    icon: <KeyRound size={16} />,
  },
  {
    value: "gcp",
    label: "Google Cloud",
    description: "Authenticate to Google Cloud services.",
    icon: <Cloud size={16} />,
  },
  {
    value: "aws",
    label: "AWS",
    description: "Sign backend requests with AWS SigV4 credentials.",
    icon: <Cloud size={16} />,
  },
  {
    value: "azure",
    label: "Azure",
    description: "Authenticate to Azure services.",
    icon: <Cloud size={16} />,
  },
  {
    value: "copilot",
    label: "GitHub Copilot",
    description: "Authenticate to GitHub Copilot.",
    icon: <Github size={16} />,
  },
  {
    value: "oauth",
    label: "OAuth token exchange",
    description: "Exchange the incoming token for a backend access token.",
    icon: <ArrowLeftRight size={16} />,
  },
  {
    value: "crossAppAccess",
    label: "Cross App Access",
    description: "Use Identity Assertion (ID-JAG) to obtain a backend token.",
    icon: <Users size={16} />,
  },
];

// RFC 8693 token-type URN — a closed set server-side (OAuthTokenType), even
// though the schema widens it to a plain string. Any other value fails to
// deserialize (collapsed into the generic BackendAuthCompat error), so this
// must be a constrained selector, not free text.
const oauthTokenTypeOptions: Array<EnumSelectorOption<string>> = [
  {
    value: "urn:ietf:params:oauth:token-type:access_token",
    label: "Access token",
  },
  { value: "urn:ietf:params:oauth:token-type:jwt", label: "JWT" },
  { value: "urn:ietf:params:oauth:token-type:id_token", label: "ID token" },
  { value: "urn:ietf:params:oauth:token-type:id-jag", label: "ID-JAG" },
];

// -- Authorization location (shared by passthrough/key/oauth token specs) --

type LocationMode = "unset" | "header" | "query" | "cookie" | "preserved";
type LocationDraft = {
  mode: LocationMode;
  headerName: string;
  headerPrefix: string;
  queryName: string;
  cookieName: string;
  preserved?: unknown;
};

function emptyLocation(): LocationDraft {
  return {
    mode: "unset",
    headerName: "",
    headerPrefix: "",
    queryName: "",
    cookieName: "",
  };
}

function locationFromValue(value: unknown): LocationDraft {
  if (!value || typeof value !== "object") return emptyLocation();
  const v = value as Record<string, unknown>;
  if (v.header && typeof v.header === "object") {
    const h = v.header as Record<string, unknown>;
    return {
      ...emptyLocation(),
      mode: "header",
      headerName: String(h.name ?? ""),
      headerPrefix: typeof h.prefix === "string" ? h.prefix : "",
    };
  }
  if (v.queryParameter && typeof v.queryParameter === "object") {
    const q = v.queryParameter as Record<string, unknown>;
    return {
      ...emptyLocation(),
      mode: "query",
      queryName: String(q.name ?? ""),
    };
  }
  if (v.cookie && typeof v.cookie === "object") {
    const c = v.cookie as Record<string, unknown>;
    return {
      ...emptyLocation(),
      mode: "cookie",
      cookieName: String(c.name ?? ""),
    };
  }
  // CEL expression sources aren't editable structurally; preserve as-is.
  return { ...emptyLocation(), mode: "preserved", preserved: value };
}

// Some callers (e.g. the RFC 8693 actor token) require a source; others
// (subjectToken) don't and fall back to a server-side default when unset.
// Only the former need this check.
function locationIsSet(draft: LocationDraft): boolean {
  return locationToValue(draft) !== undefined;
}

function locationToValue(draft: LocationDraft): unknown {
  switch (draft.mode) {
    case "unset":
      return undefined;
    case "header":
      return draft.headerName.trim()
        ? {
            header: cleanEmpty({
              name: draft.headerName.trim(),
              prefix: draft.headerPrefix.trim() || undefined,
            }),
          }
        : undefined;
    case "query":
      return draft.queryName.trim()
        ? { queryParameter: { name: draft.queryName.trim() } }
        : undefined;
    case "cookie":
      return draft.cookieName.trim()
        ? { cookie: { name: draft.cookieName.trim() } }
        : undefined;
    case "preserved":
      return draft.preserved;
  }
}

function LocationFields(props: {
  label: string;
  tooltip?: string;
  hint?: string;
  value: LocationDraft;
  onChange: (next: LocationDraft) => void;
  allowUnset?: boolean;
}) {
  const options: Array<EnumSelectorOption<LocationMode>> = [
    ...(props.allowUnset === false
      ? []
      : [{ value: "unset" as const, label: "Default" }]),
    { value: "header", label: "Header" },
    { value: "query", label: "Query parameter" },
    { value: "cookie", label: "Cookie" },
  ];
  return (
    <FieldGroup label={props.label} tooltip={props.tooltip} hint={props.hint}>
      <EnumSelector
        ariaLabel={props.label}
        value={props.value.mode === "preserved" ? "unset" : props.value.mode}
        options={options}
        onChange={(mode) => props.onChange({ ...props.value, mode })}
      />
      {props.value.mode === "preserved" ? (
        <small>
          Uses a CEL expression source; preserved as-is. Switch to Header, Query
          parameter, or Cookie to edit here.
        </small>
      ) : null}
      {props.value.mode === "header" ? (
        <div className="form-grid">
          <input
            value={props.value.headerName}
            onChange={(event) =>
              props.onChange({ ...props.value, headerName: event.target.value })
            }
            placeholder="authorization"
          />
          <input
            value={props.value.headerPrefix}
            onChange={(event) =>
              props.onChange({
                ...props.value,
                headerPrefix: event.target.value,
              })
            }
            placeholder="Bearer  (optional prefix)"
          />
        </div>
      ) : null}
      {props.value.mode === "query" ? (
        <input
          value={props.value.queryName}
          onChange={(event) =>
            props.onChange({ ...props.value, queryName: event.target.value })
          }
          placeholder="access_token"
        />
      ) : null}
      {props.value.mode === "cookie" ? (
        <input
          value={props.value.cookieName}
          onChange={(event) =>
            props.onChange({ ...props.value, cookieName: event.target.value })
          }
          placeholder="session"
        />
      ) : null}
    </FieldGroup>
  );
}

// -- Client auth (shared by oauth/crossAppAccess) --

type ClientAuthMode = "none" | "basic" | "post" | "preserved";
type ClientAuthDraft = {
  mode: ClientAuthMode;
  clientId: string;
  clientSecret: string;
  preserved?: unknown;
};

function emptyClientAuth(): ClientAuthDraft {
  return { mode: "none", clientId: "", clientSecret: "" };
}

function clientAuthFromValue(value: unknown): ClientAuthDraft {
  if (!value || typeof value !== "object") return emptyClientAuth();
  const v = value as Record<string, unknown>;
  const method = typeof v.method === "string" ? v.method : undefined;
  if (
    method === "clientSecretBasic" ||
    (method === undefined && "clientId" in v)
  ) {
    return {
      mode: "basic",
      clientId: String(v.clientId ?? ""),
      clientSecret: secretText(v.clientSecret),
    };
  }
  if (method === "clientSecretPost") {
    return {
      mode: "post",
      clientId: String(v.clientId ?? ""),
      clientSecret: secretText(v.clientSecret),
    };
  }
  // privateKeyJwt or another unrecognized method: preserve as-is.
  return {
    mode: "preserved",
    clientId: "",
    clientSecret: "",
    preserved: value,
  };
}

function secretText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value && typeof value === "object" && "file" in value) {
    return String((value as Record<string, unknown>).file ?? "");
  }
  return "";
}

// Mirrors OAuthClientAuth::validate_load: clientId is always required once a
// method is picked, and clientSecret is required specifically for Basic (for
// Post it's optional). For oauth (where clientAuth as a whole is optional),
// leaving clientId blank while "basic"/"post" is selected doesn't error at
// the JSON level — clientAuthToValue drops the whole block — but it's a
// confusing silent downgrade to "no client auth", so it's still flagged here.
function clientAuthValidationError(
  draft: ClientAuthDraft,
  label: string,
  allowNone = true,
): string | null {
  if (draft.mode === "none") {
    // Some endpoints (e.g. Cross App Access) require client authentication;
    // the schema has no "none" variant there, so surface a real message rather
    // than emitting a config that fails schema validation on save.
    return allowNone
      ? null
      : `${label} requires a client authentication method.`;
  }
  if (draft.mode === "preserved") return null;
  if (!draft.clientId.trim()) return `${label} requires a client ID.`;
  if (draft.mode === "basic" && !draft.clientSecret.trim()) {
    return `${label} requires a client secret when using Basic authentication.`;
  }
  return null;
}

// Mirrors the "must start with /" check applied to every token_endpoint_path
// (OAuthTokenExchangeAuth, CrossAppAccessEndpoint) — schema says any string.
function endpointPathError(draft: EndpointDraft, label: string): string | null {
  const path = draft.path.trim();
  return path && !path.startsWith("/")
    ? `${label} path must start with /.`
    : null;
}

function endpointHostError(draft: EndpointDraft, label: string): string | null {
  return draft.mode === "host" ? hostPortError(draft.host, label) : null;
}

function clientAuthToValue(draft: ClientAuthDraft): unknown {
  switch (draft.mode) {
    case "none":
      return undefined;
    case "preserved":
      return draft.preserved;
    case "basic":
    case "post":
      if (!draft.clientId.trim()) return undefined;
      return cleanEmpty({
        clientId: draft.clientId.trim(),
        clientSecret: draft.clientSecret.trim() || undefined,
        method:
          draft.mode === "basic" ? "clientSecretBasic" : "clientSecretPost",
      });
  }
}

function ClientAuthFields(props: {
  value: ClientAuthDraft;
  onChange: (next: ClientAuthDraft) => void;
  allowNone?: boolean;
}) {
  const options: Array<EnumSelectorOption<ClientAuthMode>> = [
    ...(props.allowNone === false
      ? []
      : [
          {
            value: "none" as const,
            label: "None",
            description:
              "No client authentication is sent (WIF-style endpoints).",
          },
        ]),
    {
      value: "basic",
      label: "Client secret (Basic)",
      description: "client_id/client_secret sent in the HTTP Basic header.",
    },
    {
      value: "post",
      label: "Client secret (POST)",
      description: "client_id/client_secret sent in the request form body.",
    },
  ];
  return (
    <FieldGroup label="Client authentication">
      <EnumSelector
        ariaLabel="Client authentication"
        value={props.value.mode === "preserved" ? "none" : props.value.mode}
        options={options}
        onChange={(mode) => props.onChange({ ...props.value, mode })}
      />
      {props.value.mode === "preserved" ? (
        <small>
          Uses privateKeyJwt client authentication; preserved as-is. Switch to
          another method to edit here.
        </small>
      ) : null}
      {props.value.mode === "basic" || props.value.mode === "post" ? (
        <div className="form-grid">
          <input
            value={props.value.clientId}
            onChange={(event) =>
              props.onChange({ ...props.value, clientId: event.target.value })
            }
            placeholder="Client ID"
          />
          <input
            value={props.value.clientSecret}
            onChange={(event) =>
              props.onChange({
                ...props.value,
                clientSecret: event.target.value,
              })
            }
            placeholder="Client secret"
          />
        </div>
      ) : null}
    </FieldGroup>
  );
}

// -- host/backend endpoint reference (shared by oauth/crossAppAccess) --

type EndpointMode = "host" | "backend" | "preserved";
type EndpointDraft = {
  mode: EndpointMode;
  host: string;
  backendRef: string;
  path: string;
  preserved?: unknown;
};

function endpointFromValue(value: unknown): EndpointDraft {
  const base = { host: "", backendRef: "", path: "" };
  if (!value || typeof value !== "object") {
    return { ...base, mode: "host" };
  }
  const v = value as Record<string, unknown>;
  const path = typeof v.path === "string" ? v.path : "";
  if (typeof v.host === "string") {
    return { ...base, mode: "host", host: v.host, path };
  }
  if (typeof v.backend === "string") {
    return { ...base, mode: "backend", backendRef: v.backend, path };
  }
  return { ...base, mode: "preserved", path, preserved: value };
}

// The Rust-side flattened endpoint (host/backend/service) has no fallback
// variant — deserialization hard-fails if none of those keys are present.
// An unset endpoint isn't "use defaults", it's an incomplete config.
function endpointIsSet(draft: EndpointDraft): boolean {
  switch (draft.mode) {
    case "preserved":
      return Boolean(draft.preserved);
    case "backend":
      return Boolean(draft.backendRef.trim());
    case "host":
      return Boolean(draft.host.trim());
  }
}

function endpointToValue(draft: EndpointDraft): Record<string, unknown> {
  const path = draft.path.trim() || undefined;
  if (draft.mode === "preserved" && draft.preserved) {
    return cleanEmpty({
      ...(draft.preserved as Record<string, unknown>),
      path,
    }) as Record<string, unknown>;
  }
  if (draft.mode === "backend") {
    return cleanEmpty({
      backend: draft.backendRef.trim(),
      path,
    }) as Record<string, unknown>;
  }
  return cleanEmpty({
    host: draft.host.trim(),
    path,
  }) as Record<string, unknown>;
}

function EndpointFields(props: {
  label: string;
  value: EndpointDraft;
  onChange: (next: EndpointDraft) => void;
}) {
  return (
    <FieldGroup label={props.label}>
      <EnumSelector
        ariaLabel={props.label}
        value={props.value.mode === "preserved" ? "host" : props.value.mode}
        options={[
          { value: "host", label: "Host" },
          { value: "backend", label: "Backend reference" },
        ]}
        onChange={(mode) => props.onChange({ ...props.value, mode })}
      />
      {props.value.mode === "preserved" ? (
        <small>
          Uses a Kubernetes Service reference; preserved as-is. Switch to Host
          or Backend reference to edit here.
        </small>
      ) : null}
      <div className="form-grid">
        {props.value.mode === "backend" ? (
          <input
            value={props.value.backendRef}
            onChange={(event) =>
              props.onChange({ ...props.value, backendRef: event.target.value })
            }
            placeholder="my-backend"
          />
        ) : props.value.mode === "host" ? (
          <input
            value={props.value.host}
            onChange={(event) =>
              props.onChange({ ...props.value, host: event.target.value })
            }
            placeholder="idp.example.com:443"
          />
        ) : null}
        <input
          value={props.value.path}
          onChange={(event) =>
            props.onChange({ ...props.value, path: event.target.value })
          }
          placeholder="/token (optional; defaults to /)"
        />
      </div>
    </FieldGroup>
  );
}

function commaList(value: string) {
  const items = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return items.length ? items : undefined;
}

function joinList(values: string[] | undefined) {
  return values?.join(", ") ?? "";
}

export function BackendAuthPolicyEditor(props: {
  formId?: string;
  backendAuth: BackendAuth | null | undefined;
  help: SchemaHelp;
  saving: boolean;
  onSave: (value: BackendAuth) => void;
}) {
  const initial = draftFromBackendAuth(props.backendAuth);
  if (initial.kind === "unsupported") {
    return (
      <UnsupportedBackendAuthFields
        formId={props.formId}
        value={props.backendAuth}
        help={props.help}
        onSave={props.onSave}
      />
    );
  }
  return <BackendAuthFields {...props} initial={initial} />;
}

function UnsupportedBackendAuthFields(props: {
  formId?: string;
  value: unknown;
  help: SchemaHelp;
  onSave: (value: BackendAuth) => void;
}) {
  const [yamlText, setYamlText] = useState(() => initialYamlText(props.value));
  const [error, setError] = useState<string | null>(null);
  const schema = props.help.node(["$defs", "BackendAuth"]);

  function save() {
    try {
      setError(null);
      props.onSave(parseSchemaYamlEditorValue(yamlText) as BackendAuth);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid YAML");
    }
  }

  return (
    <form
      id={props.formId}
      className="policy-editor-stack"
      onSubmit={(event) => {
        event.preventDefault();
        save();
      }}
    >
      <StatusBanner state="warn" title="Unsupported backend auth shape">
        This backend auth policy uses a shape the visual editor does not support
        yet. Edit the raw YAML below — it still must match one of the
        BackendAuth methods.
      </StatusBanner>
      {error ? (
        <StatusBanner state="bad" title="Invalid YAML">
          {error}
        </StatusBanner>
      ) : null}
      <FieldGroup label="Backend auth YAML">
        <SchemaYamlEditor
          path="agentgateway-policy-backend-auth-unsupported.yaml"
          schema={schema ?? {}}
          showLineNumbers={false}
          invalid={Boolean(error)}
          value={yamlText}
          onChange={(value) => {
            setYamlText(value);
            if (error) setError(null);
          }}
          onSave={save}
        />
      </FieldGroup>
    </form>
  );
}

function initialYamlText(value: unknown) {
  if (
    !value ||
    (typeof value === "object" && Object.keys(value).length === 0)
  ) {
    return "";
  }
  return toYamlText(value);
}

function BackendAuthFields(props: {
  formId?: string;
  help: SchemaHelp;
  saving: boolean;
  initial: Draft;
  onSave: (value: BackendAuth) => void;
}) {
  const [kind, setKind] = useState<AuthKind>(props.initial.kind as AuthKind);
  const [error, setError] = useState<string | null>(null);

  const [passthroughLocation, setPassthroughLocation] = useState(
    props.initial.passthrough.location,
  );

  const [keyMode, setKeyMode] = useState(props.initial.key.mode);
  const [keyValue, setKeyValue] = useState(props.initial.key.value);
  const [keyLocation, setKeyLocation] = useState(props.initial.key.location);

  const [gcpType, setGcpType] = useState(props.initial.gcp.type);
  const [gcpAudience, setGcpAudience] = useState(props.initial.gcp.audience);
  const [gcpCredentialMode, setGcpCredentialMode] = useState(
    props.initial.gcp.credentialMode,
  );
  const [gcpCredentialFile, setGcpCredentialFile] = useState(
    props.initial.gcp.credentialFile,
  );

  const [awsMode, setAwsMode] = useState(props.initial.aws.mode);
  const [awsAccessKeyId, setAwsAccessKeyId] = useState(
    props.initial.aws.accessKeyId,
  );
  const [awsSecretAccessKey, setAwsSecretAccessKey] = useState(
    props.initial.aws.secretAccessKey,
  );
  const [awsRegion, setAwsRegion] = useState(props.initial.aws.region);
  const [awsSessionToken, setAwsSessionToken] = useState(
    props.initial.aws.sessionToken,
  );
  const [awsServiceName, setAwsServiceName] = useState(
    props.initial.aws.serviceName,
  );
  const [awsAssumeRoleArn, setAwsAssumeRoleArn] = useState(
    props.initial.aws.assumeRoleArn,
  );

  const [azureMode, setAzureMode] = useState(props.initial.azure.mode);
  const [azureTenantId, setAzureTenantId] = useState(
    props.initial.azure.tenantId,
  );
  const [azureClientId, setAzureClientId] = useState(
    props.initial.azure.clientId,
  );
  const [azureClientSecret, setAzureClientSecret] = useState(
    props.initial.azure.clientSecret,
  );
  const [azureIdentityKind, setAzureIdentityKind] = useState(
    props.initial.azure.identityKind,
  );
  const [azureIdentityValue, setAzureIdentityValue] = useState(
    props.initial.azure.identityValue,
  );

  const [oauthEndpoint, setOauthEndpoint] = useState(
    props.initial.oauth.endpoint,
  );
  const [oauthGrantType, setOauthGrantType] = useState(
    props.initial.oauth.grantType,
  );
  const [oauthSubjectLocation, setOauthSubjectLocation] = useState(
    props.initial.oauth.subjectLocation,
  );
  const [oauthSubjectTokenType, setOauthSubjectTokenType] = useState(
    props.initial.oauth.subjectTokenType,
  );
  const [oauthActorEnabled, setOauthActorEnabled] = useState(
    props.initial.oauth.actorEnabled,
  );
  const [oauthActorLocation, setOauthActorLocation] = useState(
    props.initial.oauth.actorLocation,
  );
  const [oauthActorTokenType, setOauthActorTokenType] = useState(
    props.initial.oauth.actorTokenType,
  );
  const [oauthActorEnforceMayAct, setOauthActorEnforceMayAct] = useState(
    props.initial.oauth.actorEnforceMayAct,
  );
  const [oauthAudiences, setOauthAudiences] = useState(
    props.initial.oauth.audiences,
  );
  const [oauthScopes, setOauthScopes] = useState(props.initial.oauth.scopes);
  const [oauthResources, setOauthResources] = useState(
    props.initial.oauth.resources,
  );
  const [oauthRequestedTokenType, setOauthRequestedTokenType] = useState(
    props.initial.oauth.requestedTokenType,
  );
  const [oauthClientAuth, setOauthClientAuth] = useState(
    props.initial.oauth.clientAuth,
  );
  const [oauthAuthLocation, setOauthAuthLocation] = useState(
    props.initial.oauth.authLocation,
  );

  const [caaIdentityProvider, setCaaIdentityProvider] = useState(
    props.initial.crossAppAccess.identityProvider,
  );
  const [caaIdpClientAuth, setCaaIdpClientAuth] = useState(
    props.initial.crossAppAccess.idpClientAuth,
  );
  const [caaResourceServer, setCaaResourceServer] = useState(
    props.initial.crossAppAccess.resourceServer,
  );
  const [caaResClientAuth, setCaaResClientAuth] = useState(
    props.initial.crossAppAccess.resClientAuth,
  );
  const [caaAudience, setCaaAudience] = useState(
    props.initial.crossAppAccess.audience,
  );
  const [caaResources, setCaaResources] = useState(
    props.initial.crossAppAccess.resources,
  );
  const [caaScopes, setCaaScopes] = useState(
    props.initial.crossAppAccess.scopes,
  );

  function build(): BackendAuth {
    switch (kind) {
      case "passthrough":
        return {
          passthrough:
            cleanEmpty({
              location: locationToValue(passthroughLocation),
            }) ?? {},
        } as BackendAuth;
      case "key":
        return {
          key:
            cleanEmpty({
              value:
                keyMode === "file"
                  ? { file: keyValue.trim() }
                  : keyMode === "env"
                    ? keyValue.trim()
                      ? `$${keyValue.trim()}`
                      : ""
                    : keyValue.trim(),
              location: locationToValue(keyLocation),
            }) ?? {},
        } as BackendAuth;
      case "gcp":
        return {
          gcp:
            cleanEmpty({
              type: gcpType === "idToken" ? "idToken" : undefined,
              audience:
                gcpType === "idToken"
                  ? gcpAudience.trim() || undefined
                  : undefined,
              credential:
                gcpCredentialMode === "file"
                  ? { file: gcpCredentialFile.trim() }
                  : undefined,
            }) ?? {},
        } as BackendAuth;
      case "aws":
        return {
          aws:
            (awsMode === "static"
              ? cleanEmpty({
                  accessKeyId: awsAccessKeyId.trim(),
                  secretAccessKey: awsSecretAccessKey.trim(),
                  region: awsRegion.trim() || undefined,
                  sessionToken: awsSessionToken.trim() || undefined,
                  serviceName: awsServiceName.trim() || undefined,
                })
              : cleanEmpty({
                  serviceName: awsServiceName.trim() || undefined,
                  assumeRole: awsAssumeRoleArn.trim()
                    ? { roleArn: awsAssumeRoleArn.trim() }
                    : undefined,
                })) ?? {},
        } as BackendAuth;
      case "azure":
        return { azure: buildAzure() } as BackendAuth;
      case "copilot":
        return "copilot" as BackendAuth;
      case "oauth":
        return {
          oauthTokenExchange:
            cleanEmpty({
              ...endpointToValue(oauthEndpoint),
              grantType:
                oauthGrantType === "tokenExchange" ? undefined : oauthGrantType,
              subjectToken: cleanEmpty({
                source: locationToValue(oauthSubjectLocation),
                tokenType: oauthSubjectTokenType.trim() || undefined,
              }),
              actorToken: oauthActorEnabled
                ? cleanEmpty({
                    source: locationToValue(oauthActorLocation),
                    tokenType: oauthActorTokenType.trim() || undefined,
                    enforceMayAct: oauthActorEnforceMayAct || undefined,
                  })
                : undefined,
              audiences: commaList(oauthAudiences),
              scopes: commaList(oauthScopes),
              resources: commaList(oauthResources),
              requestedTokenType: oauthRequestedTokenType.trim() || undefined,
              clientAuth: clientAuthToValue(oauthClientAuth),
              authorizationLocation: locationToValue(oauthAuthLocation),
            }) ?? {},
        } as BackendAuth;
      case "crossAppAccess":
        return {
          crossAppAccess:
            cleanEmpty({
              identityProvider: cleanEmpty({
                ...endpointToValue(caaIdentityProvider),
                clientAuth: clientAuthToValue(caaIdpClientAuth),
              }),
              resourceAuthorizationServer: cleanEmpty({
                ...endpointToValue(caaResourceServer),
                clientAuth: clientAuthToValue(caaResClientAuth),
              }),
              audience: caaAudience.trim(),
              resources: commaList(caaResources),
              scopes: commaList(caaScopes),
            }) ?? {},
        } as BackendAuth;
    }
  }

  function buildAzure(): unknown {
    switch (azureMode) {
      case "implicit":
        return { implicit: {} };
      case "developerImplicit":
        return { developerImplicit: {} };
      case "clientSecret":
        return {
          explicitConfig: {
            clientSecret: {
              tenant_id: azureTenantId.trim(),
              client_id: azureClientId.trim(),
              client_secret: azureClientSecret.trim(),
            },
          },
        };
      case "managedIdentity":
        return {
          explicitConfig: {
            managedIdentity: cleanEmpty({
              userAssignedIdentity:
                azureIdentityKind === "none"
                  ? undefined
                  : { [azureIdentityKind]: azureIdentityValue.trim() },
            }),
          },
        };
      case "workloadIdentity":
        return { explicitConfig: { workloadIdentity: {} } };
    }
  }

  function validate(): string | null {
    if (
      kind === "aws" &&
      awsMode === "static" &&
      (!awsAccessKeyId.trim() || !awsSecretAccessKey.trim())
    ) {
      return "AWS static credentials require an access key ID and secret access key.";
    }
    if (kind === "key" && !keyValue.trim()) {
      return "A secret value is required.";
    }
    if (kind === "oauth") {
      if (!endpointIsSet(oauthEndpoint)) {
        return "OAuth token exchange requires a token endpoint (host or backend reference).";
      }
      const pathError = endpointPathError(oauthEndpoint, "Token endpoint");
      if (pathError) return pathError;
      const hostError = endpointHostError(oauthEndpoint, "Token endpoint host");
      if (hostError) return hostError;
      if (oauthGrantType === "jwtBearer") {
        if (oauthRequestedTokenType) {
          return "Requested token type is only valid with the token-exchange grant type.";
        }
        if (oauthActorEnabled) {
          return "The delegation actor token is only valid with the token-exchange grant type.";
        }
      }
      if (
        oauthRequestedTokenType === "urn:ietf:params:oauth:token-type:id-jag"
      ) {
        return "Requested token type id-jag is only supported by Cross App Access.";
      }
      if (oauthActorEnabled) {
        if (!locationIsSet(oauthActorLocation)) {
          return "The delegation actor token requires a token source (header, query parameter, or cookie).";
        }
        if (
          oauthActorEnforceMayAct &&
          oauthActorTokenType !== "urn:ietf:params:oauth:token-type:jwt"
        ) {
          return "Enforcing the may_act claim requires the actor token type to be JWT.";
        }
      }
      const clientAuthError = clientAuthValidationError(
        oauthClientAuth,
        "The token endpoint client authentication",
      );
      if (clientAuthError) return clientAuthError;
    }
    if (kind === "crossAppAccess") {
      if (!endpointIsSet(caaIdentityProvider)) {
        return "Cross App Access requires an identity provider endpoint.";
      }
      if (!endpointIsSet(caaResourceServer)) {
        return "Cross App Access requires a resource authorization server endpoint.";
      }
      // audience is a required field on the wire (the ID-JAG is bound to it),
      // and build() drops it when blank, so require it here rather than let
      // the empty config fail schema validation on save.
      if (!caaAudience.trim()) {
        return "Cross App Access requires an audience (the resource authorization server identifier).";
      }
      const idpPathError = endpointPathError(
        caaIdentityProvider,
        "Identity provider endpoint",
      );
      if (idpPathError) return idpPathError;
      const resPathError = endpointPathError(
        caaResourceServer,
        "Resource authorization server endpoint",
      );
      if (resPathError) return resPathError;
      const idpHostError = endpointHostError(
        caaIdentityProvider,
        "Identity provider host",
      );
      if (idpHostError) return idpHostError;
      const resHostError = endpointHostError(
        caaResourceServer,
        "Resource authorization server host",
      );
      if (resHostError) return resHostError;
      const idpClientAuthError = clientAuthValidationError(
        caaIdpClientAuth,
        "The identity provider",
        false,
      );
      if (idpClientAuthError) return idpClientAuthError;
      const resClientAuthError = clientAuthValidationError(
        caaResClientAuth,
        "The resource authorization server",
        false,
      );
      if (resClientAuthError) return resClientAuthError;
    }
    return null;
  }

  const preview = build();

  return (
    <form
      id={props.formId}
      className="policy-editor-stack"
      onSubmit={(event) => {
        event.preventDefault();
        const validationError = validate();
        if (validationError) {
          setError(validationError);
          return;
        }
        setError(null);
        props.onSave(preview);
      }}
    >
      {error ? (
        <StatusBanner state="bad" title="Invalid configuration">
          {error}
        </StatusBanner>
      ) : null}
      <FieldGroup
        label="Auth method"
        tooltip={props.help.definition(
          "BackendAuth",
          "Select how the gateway authenticates to the backend.",
        )}
      >
        <EnumSelector
          ariaLabel="Auth method"
          value={kind}
          options={authKindOptions}
          showSelectedDescription
          searchable
          onChange={setKind}
        />
      </FieldGroup>

      {kind === "passthrough" ? (
        <LocationFields
          label="Location"
          hint="Optional. Defaults to the Authorization header."
          value={passthroughLocation}
          onChange={setPassthroughLocation}
        />
      ) : null}

      {kind === "key" ? (
        <>
          <FieldGroup label="Secret value">
            <EnumSelector
              ariaLabel="Secret source"
              value={keyMode}
              options={[
                { value: "key", label: "Inline" },
                { value: "env", label: "Env var" },
                { value: "file", label: "File" },
              ]}
              onChange={setKeyMode}
            />
            <input
              value={keyValue}
              onChange={(event) => setKeyValue(event.target.value)}
              placeholder={
                keyMode === "env"
                  ? "ENV_VAR_NAME"
                  : keyMode === "file"
                    ? "$HOME/.secrets/backend-key"
                    : "secret-value"
              }
            />
          </FieldGroup>
          <LocationFields
            label="Location"
            hint="Optional. Defaults to the Authorization header."
            value={keyLocation}
            onChange={setKeyLocation}
          />
        </>
      ) : null}

      {kind === "gcp" ? (
        <>
          <FieldGroup label="Token type">
            <EnumSelector
              ariaLabel="Token type"
              value={gcpType}
              options={[
                { value: "accessToken", label: "Access token" },
                { value: "idToken", label: "ID token" },
              ]}
              onChange={setGcpType}
            />
          </FieldGroup>
          {gcpType === "idToken" ? (
            <Field
              label="Audience"
              hint="Optional. Defaults to the destination host."
            >
              <input
                value={gcpAudience}
                onChange={(event) => setGcpAudience(event.target.value)}
              />
            </Field>
          ) : null}
          <FieldGroup label="Credential">
            <EnumSelector
              ariaLabel="Credential"
              value={gcpCredentialMode}
              options={[
                { value: "ambient", label: "Ambient (ADC)" },
                { value: "file", label: "Service account file" },
              ]}
              onChange={setGcpCredentialMode}
            />
            {gcpCredentialMode === "file" ? (
              <input
                value={gcpCredentialFile}
                onChange={(event) => setGcpCredentialFile(event.target.value)}
                placeholder="$HOME/.secrets/gcp-sa.json"
              />
            ) : null}
          </FieldGroup>
        </>
      ) : null}

      {kind === "aws" ? (
        <>
          <FieldGroup label="Credential source">
            <EnumSelector
              ariaLabel="Credential source"
              value={awsMode}
              options={[
                { value: "implicit", label: "Ambient / IAM role" },
                { value: "static", label: "Static access keys" },
              ]}
              onChange={setAwsMode}
            />
          </FieldGroup>
          {awsMode === "static" ? (
            <div className="form-grid">
              <input
                value={awsAccessKeyId}
                onChange={(event) => setAwsAccessKeyId(event.target.value)}
                placeholder="Access key ID"
              />
              <input
                value={awsSecretAccessKey}
                onChange={(event) => setAwsSecretAccessKey(event.target.value)}
                placeholder="Secret access key"
              />
              <input
                value={awsSessionToken}
                onChange={(event) => setAwsSessionToken(event.target.value)}
                placeholder="Session token (optional)"
              />
              <input
                value={awsRegion}
                onChange={(event) => setAwsRegion(event.target.value)}
                placeholder="Region (optional)"
              />
            </div>
          ) : (
            <Field
              label="Assume role ARN"
              hint="Optional. AWS IAM role to assume before signing requests."
            >
              <input
                value={awsAssumeRoleArn}
                onChange={(event) => setAwsAssumeRoleArn(event.target.value)}
                placeholder="arn:aws:iam::123456789012:role/my-role"
              />
            </Field>
          )}
          <Field
            label="SigV4 service name"
            hint='Optional. E.g. "bedrock", "bedrock-agentcore", "execute-api".'
          >
            <input
              value={awsServiceName}
              onChange={(event) => setAwsServiceName(event.target.value)}
            />
          </Field>
        </>
      ) : null}

      {kind === "azure" ? (
        <>
          <FieldGroup label="Credential source">
            <EnumSelector
              ariaLabel="Credential source"
              value={azureMode}
              options={[
                { value: "implicit", label: "Default (ambient)" },
                { value: "developerImplicit", label: "Developer (az login)" },
                { value: "clientSecret", label: "Client secret" },
                { value: "managedIdentity", label: "Managed identity" },
                { value: "workloadIdentity", label: "Workload identity" },
              ]}
              onChange={setAzureMode}
            />
          </FieldGroup>
          {azureMode === "clientSecret" ? (
            <div className="form-grid">
              <input
                value={azureTenantId}
                onChange={(event) => setAzureTenantId(event.target.value)}
                placeholder="Tenant ID"
              />
              <input
                value={azureClientId}
                onChange={(event) => setAzureClientId(event.target.value)}
                placeholder="Client ID"
              />
              <input
                value={azureClientSecret}
                onChange={(event) => setAzureClientSecret(event.target.value)}
                placeholder="Client secret"
              />
            </div>
          ) : null}
          {azureMode === "managedIdentity" ? (
            <FieldGroup
              label="User-assigned identity"
              hint="Optional. Leave unset to use the system-assigned identity."
            >
              <EnumSelector
                ariaLabel="Identity reference"
                value={azureIdentityKind}
                options={[
                  { value: "none", label: "System-assigned" },
                  { value: "clientId", label: "Client ID" },
                  { value: "objectId", label: "Object ID" },
                  { value: "resourceId", label: "Resource ID" },
                ]}
                onChange={setAzureIdentityKind}
              />
              {azureIdentityKind !== "none" ? (
                <input
                  value={azureIdentityValue}
                  onChange={(event) =>
                    setAzureIdentityValue(event.target.value)
                  }
                />
              ) : null}
            </FieldGroup>
          ) : null}
        </>
      ) : null}

      {kind === "copilot" ? (
        <StatusBanner state="ok" title="No configuration needed">
          The gateway authenticates to GitHub Copilot automatically.
        </StatusBanner>
      ) : null}

      {kind === "oauth" ? (
        <>
          <EndpointFields
            label="Token endpoint"
            value={oauthEndpoint}
            onChange={setOauthEndpoint}
          />
          <FieldGroup label="Grant type">
            <EnumSelector
              ariaLabel="Grant type"
              value={oauthGrantType}
              options={[
                { value: "tokenExchange", label: "Token exchange (RFC 8693)" },
                { value: "jwtBearer", label: "JWT bearer (RFC 7523)" },
              ]}
              onChange={setOauthGrantType}
            />
          </FieldGroup>
          <LocationFields
            label="Subject token source"
            hint="Where the incoming token is read from. Defaults to the Authorization header."
            value={oauthSubjectLocation}
            onChange={setOauthSubjectLocation}
          />
          <Field
            label="Subject token type"
            hint="Optional. Defaults to access token."
          >
            <EnumSelector
              ariaLabel="Subject token type"
              value={oauthSubjectTokenType}
              allowEmpty
              placeholder="Default (access token)"
              options={oauthTokenTypeOptions}
              onChange={setOauthSubjectTokenType}
            />
          </Field>
          <label className="native-toggle">
            <input
              type="checkbox"
              checked={oauthActorEnabled}
              onChange={(event) => {
                const checked = event.target.checked;
                setOauthActorEnabled(checked);
                // The source picker has no "unset" option here — default it
                // to Header so a real input actually renders, instead of
                // silently staying on "unset" with nothing to fill in.
                if (checked && oauthActorLocation.mode === "unset") {
                  setOauthActorLocation({
                    ...oauthActorLocation,
                    mode: "header",
                  });
                }
              }}
            />
            <span>Include a delegation actor token (RFC 8693)</span>
          </label>
          {oauthActorEnabled ? (
            <>
              <LocationFields
                label="Actor token source"
                allowUnset={false}
                value={oauthActorLocation}
                onChange={setOauthActorLocation}
              />
              <Field
                label="Actor token type"
                hint="Optional. Defaults to access token."
              >
                <EnumSelector
                  ariaLabel="Actor token type"
                  value={oauthActorTokenType}
                  allowEmpty
                  placeholder="Default (access token)"
                  options={oauthTokenTypeOptions}
                  onChange={setOauthActorTokenType}
                />
              </Field>
              <label className="native-toggle">
                <input
                  type="checkbox"
                  checked={oauthActorEnforceMayAct}
                  onChange={(event) =>
                    setOauthActorEnforceMayAct(event.target.checked)
                  }
                />
                <span>
                  Enforce the subject's may_act claim authorizes the actor
                </span>
              </label>
            </>
          ) : null}
          <div className="form-grid">
            <Field label="Audiences" hint="Comma-separated.">
              <input
                value={oauthAudiences}
                onChange={(event) => setOauthAudiences(event.target.value)}
              />
            </Field>
            <Field label="Scopes" hint="Comma-separated.">
              <input
                value={oauthScopes}
                onChange={(event) => setOauthScopes(event.target.value)}
              />
            </Field>
            <Field label="Resources" hint="Comma-separated.">
              <input
                value={oauthResources}
                onChange={(event) => setOauthResources(event.target.value)}
              />
            </Field>
          </div>
          <Field
            label="Requested token type"
            hint="Optional. Defaults to access token."
          >
            <EnumSelector
              ariaLabel="Requested token type"
              value={oauthRequestedTokenType}
              allowEmpty
              placeholder="Default (access token)"
              options={oauthTokenTypeOptions}
              onChange={setOauthRequestedTokenType}
            />
          </Field>
          <ClientAuthFields
            value={oauthClientAuth}
            onChange={setOauthClientAuth}
          />
          <LocationFields
            label="Backend token location"
            hint="Where to place the exchanged token in the backend request. Defaults to the Authorization header."
            value={oauthAuthLocation}
            onChange={setOauthAuthLocation}
          />
        </>
      ) : null}

      {kind === "crossAppAccess" ? (
        <>
          <EndpointFields
            label="Identity provider endpoint"
            value={caaIdentityProvider}
            onChange={setCaaIdentityProvider}
          />
          <ClientAuthFields
            value={caaIdpClientAuth}
            onChange={setCaaIdpClientAuth}
            allowNone={false}
          />
          <EndpointFields
            label="Resource authorization server endpoint"
            value={caaResourceServer}
            onChange={setCaaResourceServer}
          />
          <ClientAuthFields
            value={caaResClientAuth}
            onChange={setCaaResClientAuth}
            allowNone={false}
          />
          <Field label="Audience">
            <input
              value={caaAudience}
              onChange={(event) => setCaaAudience(event.target.value)}
              placeholder="https://resource-server.example.com"
            />
          </Field>
          <div className="form-grid">
            <Field label="Resources" hint="Comma-separated.">
              <input
                value={caaResources}
                onChange={(event) => setCaaResources(event.target.value)}
              />
            </Field>
            <Field label="Scopes" hint="Comma-separated.">
              <input
                value={caaScopes}
                onChange={(event) => setCaaScopes(event.target.value)}
              />
            </Field>
          </div>
        </>
      ) : null}

      <ResultingYaml value={preview} />
    </form>
  );
}

// -- Draft parsing --

type Draft = {
  kind: AuthKind | "unsupported";
  raw?: unknown;
  passthrough: { location: LocationDraft };
  key: { mode: "key" | "env" | "file"; value: string; location: LocationDraft };
  gcp: {
    type: "accessToken" | "idToken";
    audience: string;
    credentialMode: "ambient" | "file";
    credentialFile: string;
  };
  aws: {
    mode: "static" | "implicit";
    accessKeyId: string;
    secretAccessKey: string;
    region: string;
    sessionToken: string;
    serviceName: string;
    assumeRoleArn: string;
  };
  azure: {
    mode:
      | "implicit"
      | "developerImplicit"
      | "clientSecret"
      | "managedIdentity"
      | "workloadIdentity";
    tenantId: string;
    clientId: string;
    clientSecret: string;
    identityKind: "none" | "clientId" | "objectId" | "resourceId";
    identityValue: string;
  };
  oauth: {
    endpoint: EndpointDraft;
    grantType: "tokenExchange" | "jwtBearer";
    subjectLocation: LocationDraft;
    subjectTokenType: string;
    actorEnabled: boolean;
    actorLocation: LocationDraft;
    actorTokenType: string;
    actorEnforceMayAct: boolean;
    audiences: string;
    scopes: string;
    resources: string;
    requestedTokenType: string;
    clientAuth: ClientAuthDraft;
    authLocation: LocationDraft;
  };
  crossAppAccess: {
    identityProvider: EndpointDraft;
    idpClientAuth: ClientAuthDraft;
    resourceServer: EndpointDraft;
    resClientAuth: ClientAuthDraft;
    audience: string;
    resources: string;
    scopes: string;
  };
};

function emptyDraft(kind: AuthKind): Draft {
  return {
    kind,
    passthrough: { location: emptyLocation() },
    key: { mode: "key", value: "", location: emptyLocation() },
    gcp: {
      type: "accessToken",
      audience: "",
      credentialMode: "ambient",
      credentialFile: "",
    },
    aws: {
      mode: "implicit",
      accessKeyId: "",
      secretAccessKey: "",
      region: "",
      sessionToken: "",
      serviceName: "",
      assumeRoleArn: "",
    },
    azure: {
      mode: "implicit",
      tenantId: "",
      clientId: "",
      clientSecret: "",
      identityKind: "none",
      identityValue: "",
    },
    oauth: {
      endpoint: endpointFromValue(undefined),
      grantType: "tokenExchange",
      subjectLocation: emptyLocation(),
      subjectTokenType: "",
      actorEnabled: false,
      actorLocation: emptyLocation(),
      actorTokenType: "",
      actorEnforceMayAct: false,
      audiences: "",
      scopes: "",
      resources: "",
      requestedTokenType: "",
      clientAuth: emptyClientAuth(),
      authLocation: emptyLocation(),
    },
    crossAppAccess: {
      identityProvider: endpointFromValue(undefined),
      idpClientAuth: emptyClientAuth(),
      resourceServer: endpointFromValue(undefined),
      resClientAuth: emptyClientAuth(),
      audience: "",
      resources: "",
      scopes: "",
    },
  };
}

// Anything the structured form can't fully represent is routed to the raw-YAML
// editor, which round-trips the whole object untouched on save.
function rawFallback(value: unknown): Draft {
  return { ...emptyDraft("passthrough"), kind: "unsupported", raw: value };
}

// The fields each object round-trips through the structured form. A wire field
// outside this set would be silently dropped on save, so its presence routes
// the whole policy to rawFallback instead. Drift only ever over-triggers the
// fallback (never drops data), so it stays fail-closed.
const OAUTH_KNOWN_KEYS = [
  "host", // endpoint (host mode)
  "backend", // endpoint (backend-reference mode)
  "path", // endpoint
  "grantType",
  "subjectToken",
  "actorToken",
  "audiences",
  "scopes",
  "resources",
  "requestedTokenType",
  "clientAuth",
  "authorizationLocation",
] as const;
const CAA_KNOWN_KEYS = [
  "identityProvider",
  "resourceAuthorizationServer",
  "audience",
  "resources",
  "scopes",
] as const;
// clientAuth is read off the endpoint separately, so it counts as modeled.
const CAA_ENDPOINT_KNOWN_KEYS = [
  "host",
  "backend",
  "path",
  "clientAuth",
] as const;

function hasUnknownKeys(
  value: Record<string, unknown>,
  known: readonly string[],
): boolean {
  return Object.keys(value).some((key) => !known.includes(key));
}

function draftFromBackendAuth(value: BackendAuth | null | undefined): Draft {
  if (value === "copilot") return emptyDraft("copilot");
  if (!value || typeof value !== "object") return emptyDraft("passthrough");
  const v = value as Record<string, unknown>;

  if (v.passthrough !== undefined) {
    const draft = emptyDraft("passthrough");
    const p = v.passthrough as Record<string, unknown>;
    draft.passthrough.location = locationFromValue(p.location);
    return draft;
  }
  if (v.key !== undefined) {
    const draft = emptyDraft("key");
    const k = v.key as Record<string, unknown>;
    draft.key.location = locationFromValue(k.location);
    if (typeof k.value === "object" && k.value && "file" in k.value) {
      draft.key.mode = "file";
      draft.key.value = String((k.value as Record<string, unknown>).file ?? "");
    } else if (typeof k.value === "string" && k.value.startsWith("$")) {
      draft.key.mode = "env";
      draft.key.value = k.value.slice(1);
    } else {
      draft.key.mode = "key";
      draft.key.value = typeof k.value === "string" ? k.value : "";
    }
    return draft;
  }
  if (v.gcp !== undefined) {
    const draft = emptyDraft("gcp");
    const g = v.gcp as Record<string, unknown>;
    draft.gcp.type = g.type === "idToken" ? "idToken" : "accessToken";
    draft.gcp.audience = typeof g.audience === "string" ? g.audience : "";
    if (g.credential !== undefined) {
      if (
        typeof g.credential === "object" &&
        g.credential !== null &&
        "file" in g.credential
      ) {
        draft.gcp.credentialMode = "file";
        draft.gcp.credentialFile = String(
          (g.credential as Record<string, unknown>).file ?? "",
        );
      } else {
        // An inline credential can't be represented in the structured form;
        // fall back to raw YAML so it isn't silently dropped on save.
        return rawFallback(value);
      }
    }
    return draft;
  }
  if (v.aws !== undefined) {
    const draft = emptyDraft("aws");
    const a = v.aws as Record<string, unknown>;
    if (typeof a.accessKeyId === "string") {
      draft.aws.mode = "static";
      draft.aws.accessKeyId = a.accessKeyId;
      draft.aws.secretAccessKey = String(a.secretAccessKey ?? "");
      draft.aws.region = typeof a.region === "string" ? a.region : "";
      draft.aws.sessionToken =
        typeof a.sessionToken === "string" ? a.sessionToken : "";
    } else {
      draft.aws.mode = "implicit";
      const assumeRole = a.assumeRole as Record<string, unknown> | undefined;
      if (assumeRole && Object.keys(assumeRole).some((k) => k !== "roleArn")) {
        // sessionName/tags on assumeRole aren't represented here; fall back to
        // raw YAML so they aren't silently dropped on save.
        return rawFallback(value);
      }
      draft.aws.assumeRoleArn =
        assumeRole && typeof assumeRole.roleArn === "string"
          ? assumeRole.roleArn
          : "";
    }
    draft.aws.serviceName =
      typeof a.serviceName === "string" ? a.serviceName : "";
    return draft;
  }
  if (v.azure !== undefined) {
    const draft = emptyDraft("azure");
    const az = v.azure as Record<string, unknown>;
    if (az.implicit !== undefined) draft.azure.mode = "implicit";
    else if (az.developerImplicit !== undefined)
      draft.azure.mode = "developerImplicit";
    else if (az.explicitConfig !== undefined) {
      const ec = az.explicitConfig as Record<string, unknown>;
      if (ec.clientSecret) {
        draft.azure.mode = "clientSecret";
        const cs = ec.clientSecret as Record<string, unknown>;
        draft.azure.tenantId = String(cs.tenant_id ?? "");
        draft.azure.clientId = String(cs.client_id ?? "");
        draft.azure.clientSecret = String(cs.client_secret ?? "");
      } else if (ec.managedIdentity) {
        draft.azure.mode = "managedIdentity";
        const mi = ec.managedIdentity as Record<string, unknown>;
        const identity = mi.userAssignedIdentity as
          | Record<string, unknown>
          | undefined;
        if (identity?.clientId) {
          draft.azure.identityKind = "clientId";
          draft.azure.identityValue = String(identity.clientId);
        } else if (identity?.objectId) {
          draft.azure.identityKind = "objectId";
          draft.azure.identityValue = String(identity.objectId);
        } else if (identity?.resourceId) {
          draft.azure.identityKind = "resourceId";
          draft.azure.identityValue = String(identity.resourceId);
        }
      } else if (ec.workloadIdentity) {
        draft.azure.mode = "workloadIdentity";
      }
    }
    return draft;
  }
  if (v.oauthTokenExchange !== undefined) {
    const draft = emptyDraft("oauth");
    const o = v.oauthTokenExchange as Record<string, unknown>;
    // The endpoint fields live at the top level of the token-exchange object,
    // so unmodeled keys (cache, additionalParams, policies, a service-ref
    // endpoint) route the whole policy to raw YAML.
    if (hasUnknownKeys(o, OAUTH_KNOWN_KEYS)) return rawFallback(value);
    draft.oauth.endpoint = endpointFromValue(o);
    draft.oauth.grantType =
      o.grantType === "jwtBearer" ? "jwtBearer" : "tokenExchange";
    const subjectToken = o.subjectToken as Record<string, unknown> | undefined;
    draft.oauth.subjectLocation = locationFromValue(subjectToken?.source);
    draft.oauth.subjectTokenType =
      typeof subjectToken?.tokenType === "string" ? subjectToken.tokenType : "";
    const actorToken = o.actorToken as Record<string, unknown> | undefined;
    draft.oauth.actorEnabled = Boolean(actorToken);
    if (actorToken) {
      draft.oauth.actorLocation = locationFromValue(actorToken.source);
      draft.oauth.actorTokenType =
        typeof actorToken.tokenType === "string" ? actorToken.tokenType : "";
      draft.oauth.actorEnforceMayAct = Boolean(actorToken.enforceMayAct);
    }
    draft.oauth.audiences = joinList(o.audiences as string[] | undefined);
    draft.oauth.scopes = joinList(o.scopes as string[] | undefined);
    draft.oauth.resources = joinList(o.resources as string[] | undefined);
    draft.oauth.requestedTokenType =
      typeof o.requestedTokenType === "string" ? o.requestedTokenType : "";
    draft.oauth.clientAuth = clientAuthFromValue(o.clientAuth);
    draft.oauth.authLocation = locationFromValue(o.authorizationLocation);
    return draft;
  }
  if (v.crossAppAccess !== undefined) {
    const draft = emptyDraft("crossAppAccess");
    const c = v.crossAppAccess as Record<string, unknown>;
    const idp = c.identityProvider as Record<string, unknown> | undefined;
    draft.crossAppAccess.identityProvider = endpointFromValue(idp);
    draft.crossAppAccess.idpClientAuth = clientAuthFromValue(idp?.clientAuth);
    const ras = c.resourceAuthorizationServer as
      | Record<string, unknown>
      | undefined;
    draft.crossAppAccess.resourceServer = endpointFromValue(ras);
    draft.crossAppAccess.resClientAuth = clientAuthFromValue(ras?.clientAuth);
    draft.crossAppAccess.audience =
      typeof c.audience === "string" ? c.audience : "";
    draft.crossAppAccess.resources = joinList(
      c.resources as string[] | undefined,
    );
    draft.crossAppAccess.scopes = joinList(c.scopes as string[] | undefined);
    // Unmodeled keys on the object (e.g. cache) or on a host/backend-mode
    // endpoint (e.g. endpoint-level policies) route to raw YAML. Preserved
    // (service-ref) endpoints keep their whole object, so they're exempt.
    const endpointDropsFields = (
      raw: Record<string, unknown> | undefined,
      endpoint: EndpointDraft,
    ) =>
      raw !== undefined &&
      endpoint.mode !== "preserved" &&
      hasUnknownKeys(raw, CAA_ENDPOINT_KNOWN_KEYS);
    if (
      hasUnknownKeys(c, CAA_KNOWN_KEYS) ||
      endpointDropsFields(idp, draft.crossAppAccess.identityProvider) ||
      endpointDropsFields(ras, draft.crossAppAccess.resourceServer)
    ) {
      return rawFallback(value);
    }
    return draft;
  }
  return rawFallback(value);
}
