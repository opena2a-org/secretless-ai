/**
 * Every backend HTTP exchange is bounded in time, end to end.
 *
 * The Vault and GCP Secret Manager backends talk to a server over HTTP. A
 * timer that is cleared once `fetch` resolves bounds only the wait for the
 * response headers: a server that sends its headers and then stalls the body
 * leaves `response.json()` waiting for as long as the connection stays open,
 * and a `run` that resolves a secret through it never starts the user's
 * command. And an aborted `fetch` rejects with "This operation was aborted",
 * which names neither the backend nor anything the user can do.
 *
 * `boundedFetch` puts the request, the response headers and the body read
 * under one deadline. A body read starts its own timer for whatever is left of
 * the deadline, so no timer outlives the call that needs it. When the deadline
 * passes, the caller's own error is thrown and the request is aborted, so the
 * connection is released.
 *
 * The bound is always passed by the caller, which names its source; nothing
 * here reads one from the environment, config or a flag.
 */

/** The parts of a response a backend reads. Body reads stay under the deadline. */
export interface BoundedResponse {
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export interface BoundedFetchOptions {
  /** The bound for the whole exchange, in milliseconds. */
  timeoutMs: number;
  /**
   * The error thrown when the bound passes. Built by the backend, so it can
   * name itself and say what to do. It must hold no token, header or body.
   */
  onTimeout: () => Error;
}

export async function boundedFetch(
  url: string,
  init: Omit<RequestInit, 'signal'>,
  opts: BoundedFetchOptions,
): Promise<BoundedResponse> {
  const controller = new AbortController();
  const endsAt = Date.now() + opts.timeoutMs;

  const within = <T>(work: () => Promise<T>): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        // Reject before aborting: the abort settles the losing side with an
        // AbortError, and the caller must see its own error, not that one.
        reject(opts.onTimeout());
        controller.abort();
      }, Math.max(0, endsAt - Date.now()));
    });
    return Promise.race([Promise.resolve().then(work), deadline])
      .finally(() => clearTimeout(timer));
  };

  const res = await within(() => fetch(url, { ...init, signal: controller.signal }));
  return {
    ok: res.ok,
    status: res.status,
    json: () => within(() => res.json()),
    text: () => within(() => res.text()),
  };
}

/**
 * The method and path of a request, for a timeout message. The path only: a
 * server address may carry userinfo, and a query is not ours to reprint.
 */
export function describeRequest(method: string, url: string): string {
  try {
    return `${method} ${new URL(url).pathname}`;
  } catch {
    return method;
  }
}
