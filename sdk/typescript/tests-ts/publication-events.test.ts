import { describe, expect, test } from "bun:test";
import {
  collectPublicationEvents,
  matchPublicationIssue,
  resolvePublicationClaims,
} from "../src/publication-events.js";
import type { PreparedScanPublication } from "../src/publication.js";

function publication(count = 1): PreparedScanPublication {
  return {
    scanId: "scan_example",
    uploadId: "scan_example",
    scanDirectory: "/synthetic/sealed-scan",
    destination: {
      type: "linear",
      teamId: "team_example",
      projectId: "project_example",
    },
    issues: Array.from({ length: count }, (_, index) => ({
      findingId: `finding_${index}`,
      occurrenceId: `occurrence_${index}`,
      title: `[Codex Security][HIGH] Finding ${index}`,
      description: [
        `**Finding ID:** finding_${index}`,
        `**Occurrence ID:** occurrence_${index}`,
        `Description ${index}`,
      ].join("\n"),
      priority: 2,
    })),
  };
}

function event(
  prepared: PreparedScanPublication,
  index = 0,
  overrides: {
    arguments?: Record<string, unknown>;
    error?: string;
    result?: unknown;
    server?: string;
    status?: "completed" | "failed";
    tool?: string;
  } = {},
): string {
  const issue = prepared.issues[index]!;
  return JSON.stringify({
    type: "item.completed",
    item: {
      id: `call_${index}`,
      type: "mcp_tool_call",
      server: overrides.server ?? "codex_apps",
      tool: overrides.tool ?? "linear.save_issue",
      status: overrides.status ?? "completed",
      arguments: overrides.arguments ?? {
        team: prepared.destination.teamId,
        project: prepared.destination.projectId,
        title: issue.title,
        description: issue.description,
        priority: issue.priority,
      },
      ...(overrides.status === "failed"
        ? { error: { message: overrides.error ?? "Linear rejected it." } }
        : {
            result:
              overrides.result ??
              ({
                structured_content: {
                  identifier: `SEC-${index + 1}`,
                  url: `https://linear.app/example/issue/SEC-${index + 1}`,
                },
                content: [],
              } satisfies Record<string, unknown>),
          }),
    },
  });
}

describe("Linear publication claim resolution", () => {
  const entityId = "11111111-2222-4333-8444-555555555555";
  const alternateEntityId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const identifier = "SYNTH-501";
  const url = `https://linear.app/example/issue/${identifier}`;

  test.each([
    ["older key result", { id: entityId, key: identifier, url }],
    ["current id-only result", { id: identifier }],
    ["rich result", { id: entityId, identifier, url }],
  ] as const)("resolves the %s shape", (_name, value) => {
    expect(resolvePublicationClaims(value)).toMatchObject({
      state: "resolved",
      issueIdentifier: identifier,
    });
  });

  test("treats an entity UUID without a human issue key as absent", () => {
    expect(resolvePublicationClaims({ id: entityId })).toEqual({
      state: "absent",
      claims: [{ kind: "entityId", value: entityId }],
    });
  });

  test.each(["identifier", "issueIdentifier", "key", "id"] as const)(
    "classifies a canonical UUID from %s as an entity ID",
    (field) => {
      expect(resolvePublicationClaims({ [field]: entityId })).toEqual({
        state: "absent",
        claims: [{ kind: "entityId", value: entityId }],
      });
    },
  );

  test("canonicalizes UUID spelling without changing human issue-key spelling", () => {
    const uppercaseEntityId = alternateEntityId.toUpperCase();
    expect(
      resolvePublicationClaims({
        id: uppercaseEntityId,
        structured_content: { id: alternateEntityId },
      }),
    ).toEqual({
      state: "absent",
      claims: [{ kind: "entityId", value: alternateEntityId }],
    });

    const lowercaseIdentifier = identifier.toLowerCase();
    expect(
      resolvePublicationClaims({
        identifier,
        structured_content: { identifier: lowercaseIdentifier },
      }),
    ).toEqual({
      state: "conflicting",
      claims: [
        { kind: "identifier", value: identifier },
        { kind: "identifier", value: lowercaseIdentifier },
      ],
    });
  });

  test("normalizes surrounding whitespace before classifying issue identities", () => {
    expect(
      resolvePublicationClaims({
        id: ` \t${entityId}\n`,
        issueIdentifier: `\n${entityId} `,
        key: ` ${identifier}\t`,
        url: `\n${url} `,
      }),
    ).toEqual({
      state: "resolved",
      claims: [
        { kind: "identifier", value: identifier },
        { kind: "entityId", value: entityId },
        { kind: "url", value: url },
      ],
      issueIdentifier: identifier,
      url,
    });
    expect(
      resolvePublicationClaims({ issueIdentifier: ` ${entityId}\n` }),
    ).toEqual({
      state: "absent",
      claims: [{ kind: "entityId", value: entityId }],
    });
  });

  test("deduplicates a relabeled entity ID while retaining its human key", () => {
    expect(
      resolvePublicationClaims({
        id: entityId,
        issueIdentifier: entityId,
        key: identifier,
      }),
    ).toEqual({
      state: "resolved",
      claims: [
        { kind: "identifier", value: identifier },
        { kind: "entityId", value: entityId },
      ],
      issueIdentifier: identifier,
    });
  });

  test("rejects one opaque value claimed as both an entity ID and human identifier", () => {
    const opaqueIdentity = "synthetic-opaque-entity";
    expect(
      resolvePublicationClaims({
        id: opaqueIdentity,
        issueIdentifier: opaqueIdentity,
      }),
    ).toEqual({
      state: "conflicting",
      claims: [
        { kind: "identifier", value: opaqueIdentity },
        { kind: "entityId", value: opaqueIdentity },
      ],
    });
  });

  test("resolves a human issue key through 20,000 nested untrusted carrier layers", () => {
    let carrier: Record<string, unknown> = { identifier: "SYNTH-20000" };
    for (let depth = 0; depth < 20_000; depth += 1) {
      carrier = { structured_content: { issue: { issue: carrier } } };
    }

    expect(resolvePublicationClaims(carrier)).toMatchObject({
      state: "resolved",
      issueIdentifier: "SYNTH-20000",
    });
  });

  test("terminates cyclic untrusted carriers while retaining their claims", () => {
    const carrier: Record<string, unknown> = { identifier };
    carrier["structured_content"] = { issue: carrier };

    expect(resolvePublicationClaims(carrier)).toMatchObject({
      state: "resolved",
      issueIdentifier: identifier,
    });
  });

  test.each(["SYNTH", "SYNTH-NOT-A-NUMBER", "501"])(
    "ignores a non-issue key value from key: %s",
    (key) => {
      expect(resolvePublicationClaims({ key })).toEqual({
        state: "absent",
        claims: [],
      });
    },
  );

  test("merges nested carriers independently of field placement", () => {
    const expected: ReturnType<typeof resolvePublicationClaims> = {
      state: "resolved",
      claims: [
        { kind: "identifier", value: identifier },
        { kind: "entityId", value: entityId },
        { kind: "url", value: url },
      ],
      issueIdentifier: identifier,
      url,
    };
    const carriers = [
      { id: entityId, key: identifier, url },
      { structured_content: { issue: { id: entityId, key: identifier, url } } },
      {
        structuredContent: {
          data: { issue: { id: entityId, identifier, url } },
        },
      },
      {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              data: {
                issue: { id: entityId, issueIdentifier: identifier, url },
              },
            }),
          },
        ],
      },
      {
        id: entityId,
        structured_content: { data: { issue: { identifier } } },
        content: [{ type: "text", text: JSON.stringify({ issue: { url } }) }],
      },
      {
        url,
        structuredContent: { issue: { id: entityId } },
        content: [
          {
            type: "text",
            text: JSON.stringify({
              data: { issue: { issueIdentifier: identifier } },
            }),
          },
        ],
      },
    ];

    for (const carrier of carriers) {
      expect(resolvePublicationClaims(carrier)).toEqual(expected);
    }
  });

  test.each([
    [
      "human identifiers",
      {
        identifier: "SYNTH-601",
        structured_content: { issueIdentifier: "SYNTH-602" },
      },
      "identifier",
    ],
    [
      "entity IDs",
      {
        identifier,
        id: entityId,
        structured_content: { issue: { id: alternateEntityId } },
      },
      "entityId",
    ],
    [
      "URLs",
      {
        identifier,
        url,
        content: [
          {
            type: "text",
            text: JSON.stringify({
              url: "https://linear.app/example/issue/SYNTH-OTHER",
            }),
          },
        ],
      },
      "url",
    ],
  ] as const)("conflicts only within %s", (_name, value, kind) => {
    const resolution = resolvePublicationClaims(value);
    expect(resolution.state).toBe("conflicting");
    expect(
      new Set(
        resolution.claims
          .filter((claim) => claim.kind === kind)
          .map((claim) => claim.value),
      ).size,
    ).toBe(2);
  });

  test("deduplicates equal claims by semantic kind", () => {
    expect(
      resolvePublicationClaims({
        id: entityId,
        identifier,
        url,
        structured_content: {
          issue: { id: entityId, issueIdentifier: identifier, url },
        },
        content: [
          {
            type: "text",
            text: JSON.stringify({ id: entityId, key: identifier, url }),
          },
        ],
      }),
    ).toEqual({
      state: "resolved",
      claims: [
        { kind: "identifier", value: identifier },
        { kind: "entityId", value: entityId },
        { kind: "url", value: url },
      ],
      issueIdentifier: identifier,
      url,
    });
  });

  test.each([
    ["root", { identifier: "SYNTH-1" }],
    ["structured", { structured_content: { issueIdentifier: "SYNTH-1" } }],
    [
      "structured alias",
      { structuredContent: { data: { issue: { id: "SYNTH-1" } } } },
    ],
    [
      "JSON text",
      {
        content: [
          {
            type: "text",
            text: JSON.stringify({ issue: { identifier: "SYNTH-1" } }),
          },
        ],
      },
    ],
  ] as const)("resolves an identifier from the %s carrier", (_name, value) => {
    expect(resolvePublicationClaims(value)).toMatchObject({
      state: "resolved",
      issueIdentifier: "SYNTH-1",
      claims: [{ kind: "identifier", value: "SYNTH-1" }],
    });
  });

  test("collects identifier and URL claims independently", () => {
    expect(
      resolvePublicationClaims({
        identifier: "SYNTH-1",
        structured_content: {
          url: "https://linear.app/example/issue/SYNTH-1",
        },
      }),
    ).toEqual({
      state: "resolved",
      issueIdentifier: "SYNTH-1",
      url: "https://linear.app/example/issue/SYNTH-1",
      claims: [
        { kind: "identifier", value: "SYNTH-1" },
        {
          kind: "url",
          value: "https://linear.app/example/issue/SYNTH-1",
        },
      ],
    });
    expect(
      resolvePublicationClaims({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              url: "https://linear.app/example/issue/SYNTH-URL",
            }),
          },
        ],
      }),
    ).toEqual({
      state: "absent",
      claims: [
        {
          kind: "url",
          value: "https://linear.app/example/issue/SYNTH-URL",
        },
      ],
    });
  });

  test.each([
    [
      "root/structured identifiers",
      {
        identifier: "SYNTH-A",
        structured_content: { identifier: "SYNTH-B" },
      },
    ],
    [
      "structured/root identifiers",
      {
        identifier: "SYNTH-B",
        structured_content: { identifier: "SYNTH-A" },
      },
    ],
    [
      "root/JSON identifiers",
      {
        identifier: "SYNTH-A",
        content: [
          {
            type: "text",
            text: JSON.stringify({ identifier: "SYNTH-B" }),
          },
        ],
      },
    ],
    [
      "JSON/root identifiers",
      {
        identifier: "SYNTH-B",
        content: [
          {
            type: "text",
            text: JSON.stringify({ identifier: "SYNTH-A" }),
          },
        ],
      },
    ],
    [
      "root/structured URL-only",
      {
        identifier: "SYNTH-SAME",
        url: "https://linear.app/example/issue/SYNTH-A",
        structured_content: {
          url: "https://linear.app/example/issue/SYNTH-B",
        },
      },
    ],
    [
      "structured/root URL-only",
      {
        url: "https://linear.app/example/issue/SYNTH-B",
        structured_content: {
          identifier: "SYNTH-SAME",
          url: "https://linear.app/example/issue/SYNTH-A",
        },
      },
    ],
    [
      "root/JSON URL-only",
      {
        identifier: "SYNTH-SAME",
        url: "https://linear.app/example/issue/SYNTH-A",
        content: [
          {
            type: "text",
            text: JSON.stringify({
              url: "https://linear.app/example/issue/SYNTH-B",
            }),
          },
        ],
      },
    ],
    [
      "structured/JSON URLs",
      {
        structured_content: {
          identifier: "SYNTH-SAME",
          url: "https://linear.app/example/issue/SYNTH-A",
        },
        content: [
          {
            type: "text",
            text: JSON.stringify({
              url: "https://linear.app/example/issue/SYNTH-B",
            }),
          },
        ],
      },
    ],
    ["identity aliases", { identifier: "SYNTH-A", issueIdentifier: "SYNTH-B" }],
  ] as const)("keeps conflicting %s", (_name, value) => {
    const resolution = resolvePublicationClaims(value);
    expect(resolution.state).toBe("conflicting");
    expect(resolution.claims.length).toBeGreaterThanOrEqual(2);
  });

  test("accepts repeated equal claims across every carrier", () => {
    const identifier = "SYNTH-777";
    const url = `https://linear.app/example/issue/${identifier}`;
    expect(
      resolvePublicationClaims({
        identifier,
        url,
        structured_content: {
          issueIdentifier: identifier,
          url,
        },
        content: [
          {
            type: "text",
            text: JSON.stringify({ id: identifier, url }),
          },
        ],
      }),
    ).toMatchObject({
      state: "resolved",
      issueIdentifier: identifier,
      url,
    });
  });
});

describe("Linear publication event evidence", () => {
  test("normalizes completed, unknown-owner, wrong-argument, and failed calls in order", () => {
    const prepared = publication(2);
    const exact = event(prepared, 0);
    const unknown = event(prepared, 0, {
      arguments: { description: "No publication identity" },
      result: { identifier: "SYNTH-UNKNOWN" },
    });
    const issue = prepared.issues[1]!;
    const wrongArguments = event(prepared, 1, {
      arguments: {
        team: "team_unexpected",
        project: prepared.destination.projectId,
        title: issue.title,
        description: issue.description,
        priority: issue.priority,
      },
      result: {
        structured_content: {
          url: "https://linear.app/example/issue/SYNTH-RESERVED",
        },
      },
    });
    const rejected = event(prepared, 1, {
      status: "failed",
      error: "Linear rejected the retry.",
    });

    expect(
      collectPublicationEvents(
        [exact, unknown, wrongArguments, rejected].join("\n"),
        prepared,
        "missing",
      ),
    ).toEqual([
      {
        source: "event",
        status: "completed",
        rawLine: exact,
        ownerFindingId: "finding_0",
        argumentsValid: true,
        resolution: {
          state: "resolved",
          issueIdentifier: "SEC-1",
          url: "https://linear.app/example/issue/SEC-1",
          claims: [
            { kind: "identifier", value: "SEC-1" },
            {
              kind: "url",
              value: "https://linear.app/example/issue/SEC-1",
            },
          ],
        },
      },
      {
        source: "event",
        status: "completed",
        rawLine: unknown,
        argumentsValid: false,
        resolution: {
          state: "resolved",
          issueIdentifier: "SYNTH-UNKNOWN",
          claims: [{ kind: "identifier", value: "SYNTH-UNKNOWN" }],
        },
      },
      {
        source: "event",
        status: "completed",
        rawLine: wrongArguments,
        ownerFindingId: "finding_1",
        argumentsValid: false,
        resolution: {
          state: "absent",
          claims: [
            {
              kind: "url",
              value: "https://linear.app/example/issue/SYNTH-RESERVED",
            },
          ],
        },
      },
      {
        source: "event",
        status: "failed",
        rawLine: rejected,
        ownerFindingId: "finding_1",
        argumentsValid: true,
        resolution: { state: "absent", claims: [] },
        error: "Linear rejected the retry.",
      },
    ]);
  });

  test.each([
    [
      "identifier",
      { structured_content: { identifier: "SYNTH-FAILED" } },
      {
        state: "resolved",
        issueIdentifier: "SYNTH-FAILED",
        claims: [{ kind: "identifier", value: "SYNTH-FAILED" }],
      },
    ],
    [
      "URL",
      {
        structured_content: {
          url: "https://linear.app/example/issue/SYNTH-FAILED",
        },
      },
      {
        state: "absent",
        claims: [
          {
            kind: "url",
            value: "https://linear.app/example/issue/SYNTH-FAILED",
          },
        ],
      },
    ],
  ] as const)(
    "retains %s claims from a failed result without an error",
    (_name, result, resolution) => {
      const prepared = publication();
      const terminal = JSON.parse(event(prepared, 0, { status: "failed" })) as {
        item: Record<string, unknown>;
      };
      delete terminal.item["error"];
      terminal.item["result"] = result;
      const rawLine = JSON.stringify(terminal);

      expect(
        collectPublicationEvents(rawLine, prepared, "Synthetic failure."),
      ).toEqual([
        {
          source: "event",
          status: "failed",
          rawLine,
          ownerFindingId: "finding_0",
          argumentsValid: true,
          resolution: {
            ...resolution,
            claims: resolution.claims.map((claim) => ({ ...claim })),
          },
          error: "Synthetic failure.",
        },
      ]);
    },
  );

  test.each([
    ["dotted", "linear.save_issue"],
    ["legacy", "linear_save_issue"],
  ] as const)("recognizes the %s tool name", (_name, tool) => {
    const prepared = publication();
    expect(
      collectPublicationEvents(
        event(prepared, 0, { tool }),
        prepared,
        "missing",
      ),
    ).toHaveLength(1);
  });

  test.each([
    ["unrelated tool", { tool: "linear.update_issue" }],
    ["spoofed suffix", { tool: "linear.save_issue.unverified" }],
    ["wrong server", { server: "untrusted_apps" }],
  ] as const)("ignores %s", (_name, overrides) => {
    const prepared = publication();
    expect(
      collectPublicationEvents(
        event(prepared, 0, overrides),
        prepared,
        "missing",
      ),
    ).toEqual([]);
  });

  test("retains both completed calls and their raw order", () => {
    const prepared = publication();
    const absent = event(prepared, 0, {
      result: { structured_content: { title: "No identifier" } },
    });
    const resolved = event(prepared, 0, {
      result: { structured_content: { identifier: "SYNTH-DUPLICATE" } },
    });
    const evidence = collectPublicationEvents(
      `${absent}\n${resolved}`,
      prepared,
      "missing",
    );
    expect(evidence.map((item) => item.rawLine)).toEqual([absent, resolved]);
    expect(evidence.map((item) => item.status)).toEqual([
      "completed",
      "completed",
    ]);
  });

  test("matches unique exact arguments before incidental sibling identifiers", () => {
    const prepared = publication(2);
    const [first, sibling] = prepared.issues;
    first!.description += `\nRepository text: ${sibling!.findingId} ${sibling!.occurrenceId}`;
    const rawLine = event(prepared, 0);
    const completed = JSON.parse(rawLine) as {
      item: { arguments: Record<string, unknown> };
    };

    expect(matchPublicationIssue(prepared, completed.item.arguments)).toBe(
      first,
    );
    expect(
      collectPublicationEvents(rawLine, prepared, "missing"),
    ).toMatchObject([
      {
        ownerFindingId: first!.findingId,
        argumentsValid: true,
      },
    ]);
  });

  test("matches finding and occurrence identifiers only at token boundaries", () => {
    const prepared = publication(2);
    const first = prepared.issues[0]!;
    expect(
      matchPublicationIssue(prepared, { description: first.description }),
    ).toBe(first);
    for (const description of [
      first.findingId,
      first.occurrenceId,
      `${first.findingId}-suffix ${first.occurrenceId}`,
      `${first.findingId} ${first.occurrenceId} finding_1 occurrence_1`,
    ]) {
      expect(matchPublicationIssue(prepared, { description })).toBeUndefined();
    }
  });
});
