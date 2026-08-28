import { startFindingsServer } from "./server.js";
import { SqliteFindingsStore } from "./sqlite-store.js";
import { OpenAiFindingEmbedder } from "./embeddings.js";
import { openAiApiKey } from "../auth.js";

export async function serveFindings(
  environment: NodeJS.ProcessEnv = process.env,
  output: Pick<NodeJS.WriteStream, "write"> = process.stdout,
): Promise<void> {
  const host = environment["HOST"] ?? "127.0.0.1";
  const port = Number(environment["PORT"] ?? 3000);
  const server = await startFindingsServer({
    store: new SqliteFindingsStore(environment),
    embeddings: new OpenAiFindingEmbedder(openAiApiKey(environment)),
    host,
    port,
  });
  const address = server.address();
  if (address !== null && typeof address !== "string") {
    output.write(
      `Findings service listening on ${address.address}:${address.port}\n`,
    );
  }

  const shutdown = () => {
    server.close((error) => {
      if (error !== undefined) {
        console.error(error);
        process.exitCode = 1;
      }
    });
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}
