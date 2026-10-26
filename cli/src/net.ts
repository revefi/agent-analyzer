/** What to tell the user when a request to host never got a response. */
export function unreachable(err: unknown, host: string, env: NodeJS.ProcessEnv): string {
  const e = err as Error & { cause?: { code?: string; message?: string } };
  if (e.name === "TimeoutError") return `${host} didn't respond in time. Try again in a few minutes.`;
  const why = e.cause?.code ?? e.cause?.message ?? e.message;
  const proxied = (env.HTTPS_PROXY || env.https_proxy) && !env.NODE_USE_ENV_PROXY;
  const hint = proxied ? " You have HTTPS_PROXY set; Node uses it only when NODE_USE_ENV_PROXY=1 is also set." : "";
  return `Couldn't reach ${host} (${why}). Check your connection and try again.${hint}`;
}
