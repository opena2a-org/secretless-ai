/**
 * A GCP Secret Manager project held in memory, for the gcp-sm backend's tests.
 *
 * `fetch` answers the REST requests the backend sends, for one project only:
 * a request to any other host or project, or one it has no route for, throws,
 * so no test reaches a real API. It keeps the API's rules the tests depend on:
 * a secret id is 1 to 255 of [A-Za-z0-9_-], creating an existing secret is
 * 409, a list is paged and carries each secret's labels, and reading or adding
 * a version of a secret that does not exist is 404.
 */

export interface FakeSecret {
  labels: Record<string, string>;
  /** Version values, oldest first. */
  versions: string[];
}

export interface FakeResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export interface FakeSecretManager {
  readonly projectId: string;
  readonly secrets: Map<string, FakeSecret>;
  /** Every request answered, as `METHOD /path?query`. */
  readonly requests: string[];
  /** The secret id of each version access that returned a value, in order. */
  readonly valueReads: string[];
  /** Add a secret holding one version with `value`. */
  put(name: string, value: string, labels?: Record<string, string>): void;
  /** The value of the latest version of `name`, or undefined. */
  latest(name: string): string | undefined;
  fetch(url: string, init?: { method?: string; body?: string }): Promise<FakeResponse>;
}

const HOST = 'secretmanager.googleapis.com';
/** Resource names in API answers carry the project number, as the real API's do. */
const PROJECT_NUMBER = '204811230977';
const SECRET_ID = /^[A-Za-z0-9_-]{1,255}$/;
const DEFAULT_PAGE_SIZE = 25;

function respond(status: number, body: unknown = {}): FakeResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

export function fakeSecretManager(projectId: string): FakeSecretManager {
  const secrets = new Map<string, FakeSecret>();
  const requests: string[] = [];
  const valueReads: string[] = [];

  const resource = (id: string) => {
    const secret = secrets.get(id)!;
    return {
      name: `projects/${PROJECT_NUMBER}/secrets/${id}`,
      replication: { automatic: {} },
      createTime: '2026-10-24T00:00:00Z',
      // The API leaves out an empty label map.
      ...(Object.keys(secret.labels).length > 0 ? { labels: { ...secret.labels } } : {}),
    };
  };

  const fetch = async (input: string, init?: { method?: string; body?: string }): Promise<FakeResponse> => {
    const url = new URL(input);
    if (url.host !== HOST) throw new Error(`fake Secret Manager: refused a request to ${url.host}`);
    const method = init?.method ?? 'GET';
    requests.push(`${method} ${url.pathname}${url.search}`);

    const base = `/v1/projects/${projectId}/secrets`;
    if (url.pathname !== base && !url.pathname.startsWith(`${base}/`)) {
      throw new Error(`fake Secret Manager: refused a request outside project ${projectId}: ${url.pathname}`);
    }
    const rest = url.pathname.slice(base.length);

    if (rest === '' && method === 'GET') {
      const size = Number(url.searchParams.get('pageSize') ?? DEFAULT_PAGE_SIZE) || DEFAULT_PAGE_SIZE;
      const start = Number(url.searchParams.get('pageToken') ?? '0');
      const ids = [...secrets.keys()].sort();
      const page = ids.slice(start, start + size);
      const next = start + size < ids.length ? String(start + size) : undefined;
      return respond(200, {
        secrets: page.map(resource),
        ...(next ? { nextPageToken: next } : {}),
        totalSize: ids.length,
      });
    }

    if (rest === '' && method === 'POST') {
      const id = url.searchParams.get('secretId') ?? '';
      if (!SECRET_ID.test(id)) return respond(400, { error: { code: 400, status: 'INVALID_ARGUMENT' } });
      if (secrets.has(id)) return respond(409, { error: { code: 409, status: 'ALREADY_EXISTS' } });
      const body = JSON.parse(init?.body ?? '{}') as { labels?: Record<string, string> };
      secrets.set(id, { labels: { ...(body.labels ?? {}) }, versions: [] });
      return respond(200, resource(id));
    }

    const access = /^\/([^/]+)\/versions\/latest:access$/.exec(rest);
    if (access && method === 'GET') {
      const secret = secrets.get(access[1]);
      if (!secret || secret.versions.length === 0) return respond(404, { error: { code: 404, status: 'NOT_FOUND' } });
      valueReads.push(access[1]);
      const version = secret.versions.length;
      return respond(200, {
        name: `projects/${PROJECT_NUMBER}/secrets/${access[1]}/versions/${version}`,
        payload: { data: Buffer.from(secret.versions[version - 1], 'utf-8').toString('base64') },
      });
    }

    const add = /^\/([^/]+):addVersion$/.exec(rest);
    if (add && method === 'POST') {
      const secret = secrets.get(add[1]);
      if (!secret) return respond(404, { error: { code: 404, status: 'NOT_FOUND' } });
      const body = JSON.parse(init?.body ?? '{}') as { payload?: { data?: string } };
      secret.versions.push(Buffer.from(body.payload?.data ?? '', 'base64').toString('utf-8'));
      return respond(200, {
        name: `projects/${PROJECT_NUMBER}/secrets/${add[1]}/versions/${secret.versions.length}`,
        state: 'ENABLED',
      });
    }

    const one = /^\/([^/:]+)$/.exec(rest);
    if (one && method === 'GET') {
      return secrets.has(one[1]) ? respond(200, resource(one[1])) : respond(404, { error: { code: 404, status: 'NOT_FOUND' } });
    }
    if (one && method === 'DELETE') {
      return secrets.delete(one[1]) ? respond(200, {}) : respond(404, { error: { code: 404, status: 'NOT_FOUND' } });
    }

    throw new Error(`fake Secret Manager: no route for ${method} ${url.pathname}`);
  };

  return {
    projectId,
    secrets,
    requests,
    valueReads,
    put(name, value, labels = {}) {
      secrets.set(name, { labels: { ...labels }, versions: [value] });
    },
    latest(name) {
      const versions = secrets.get(name)?.versions;
      return versions && versions.length > 0 ? versions[versions.length - 1] : undefined;
    },
    fetch,
  };
}
