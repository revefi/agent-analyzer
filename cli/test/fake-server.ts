export interface Seen {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | Uint8Array;
}

export type Handler = (req: Seen) => Response | Promise<Response>;

export const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

/**
 * A fetch stand-in keyed by "METHOD /path". A list of handlers is consumed in order and its last
 * entry repeats, so a route can change its answer over successive calls.
 */
export function fakeFetch(routes: Record<string, Handler[] | Handler>) {
  const seen: Seen[] = [];
  const fetchImpl = async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const body =
      init?.body instanceof Blob ? new Uint8Array(await init.body.arrayBuffer()) : (init?.body as string | undefined);
    const req: Seen = { method, url, headers: { ...(init?.headers as Record<string, string>) }, body };
    seen.push(req);
    const key = `${method} ${new URL(url).pathname}`;
    const route = routes[key];
    if (!route) throw new TypeError(`no route for ${key}`);
    const handler = Array.isArray(route) ? (route.length > 1 ? route.shift() : route[0]) : route;
    if (!handler) throw new TypeError(`no handler left for ${key}`);
    return handler(req);
  };
  return { fetch: fetchImpl as typeof fetch, seen };
}
