import axios from 'axios';
import { promises as fs } from 'fs';
import * as readline from 'readline';
import { WebSocket } from 'ws';

// Logger setup
class Logger {
  private name: string;
  
  constructor(name: string) {
    this.name = name;
  }

  info(message: string): void {
    console.info(`${this.name} INFO: ${message}`);
  }

  warning(message: string): void {
    console.warn(`${this.name} WARNING: ${message}`);
  }

  error(message: string): void {
    console.error(`${this.name} ERROR: ${message}`);
  }

  debug(message: string): void {
    console.debug(`${this.name} DEBUG: ${message}`);
  }
}

const logger = new Logger("databutton-app-mcp");

// Safe base64url decode
function safeBase64urlDecode(data: string): Buffer {
  data = data.trim();
  const padding = '='.repeat((-data.length) % 4);
  return Buffer.from(data + padding, 'base64url');
}

// Decode base64 JSON
function decodeBase64Json(b: string): any {
  return JSON.parse(safeBase64urlDecode(b).toString());
}

// Parse API key
function parseApikey(apikey: string): Record<string, string> {
  if (!apikey) {
    throw new Error("API key must be provided");
  }

  try {
    const decoded = Buffer.from(apikey, 'base64url').toString();
    return JSON.parse(decoded);
  } catch (e) {
    // Continue with next method
  }

  try {
    const decoded = Buffer.from(apikey, 'base64').toString();
    return JSON.parse(decoded);
  } catch (e) {
    // Continue with next method
  }

  try {
    return JSON.parse(apikey);
  } catch (e) {
    // Last attempt failed
  }

  throw new Error("Invalid API key");
}

// Get access token
async function getAccessToken(refreshToken: string): Promise<string> {
  const publicFirebaseApiKey = "AIzaSyAdgR9BGfQrV2fzndXZLZYgiRtpydlq8ug";
  const response = await axios.post(
    `https://securetoken.googleapis.com/v1/token?key=${publicFirebaseApiKey}`,
    `grant_type=refresh_token&refresh_token=${refreshToken}`,
    {
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    }
  );
  return response.data.id_token;
}

// Interpret API key
async function interpretApikey(apikey: string): Promise<[string, string | null]> {
  const prefix = "dbtk-v1-";
  if (apikey.startsWith(prefix)) {
    const apikeyContents = decodeBase64Json(apikey.replace(prefix, ""));
    const bearer = await getAccessToken(apikeyContents.tok);
    const bearerClaims = decodeBase64Json(bearer.split(".")[1]);
    const dbtnClaims = bearerClaims.dbtn;
    const appId = dbtnClaims.appId;
    const env = dbtnClaims.env;
    const uri = `wss://api.databutton.com/_projects/${appId}/dbtn/${env}/app/mcp/ws`;
    return [uri, bearer];
  } else {
    // Legacy API key format
    const dbtnClaims = parseApikey(apikey);
    const uri = dbtnClaims.uri;
    if (!uri) {
      throw new Error("Missing URI in api key");
    }
    if (!(
      uri.startsWith("ws://localhost") ||
      uri.startsWith("ws://127.0.0.1:") ||
      uri.startsWith("wss://")
    )) {
      throw new Error("URI must start with 'ws://' or 'wss://'");
    }
    return [uri, dbtnClaims.authCode || null];
  }
}

// WebSocket proxy functions
async function stdinToWs(websocket: WebSocket) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  });

  rl.on('line', (line) => {
    if (websocket.readyState === WebSocket.OPEN) {
      websocket.send(line);
    }
  });

  rl.on('close', () => {
    websocket.close();
  });
}

function wsToStdout(websocket: WebSocket) {
  websocket.on('message', (message) => {
    console.log(message.toString());
  });
}

// Run WebSocket proxy
async function runWsProxy(uri: string, bearer: string | null = null) {
  logger.info(`Connecting to mcp server at ${uri}`);

  const useSSL = uri.startsWith("wss://");
  if (!useSSL) {
    logger.warning("Using insecure websocket connection");
  }

  // Handle signals for graceful exit
  process.on('SIGINT', () => {
    logger.error("Connection terminated by SIGINT");
    process.exit(0);
  });
  
  process.on('SIGTERM', () => {
    logger.error("Connection terminated by SIGTERM");
    process.exit(0);
  });

  try {
    const websocket = new WebSocket(uri, ['mcp'], {
      headers: bearer ? { 'Authorization': `Bearer ${bearer}` } : {},
      handshakeTimeout: 60000,
      perMessageDeflate: false,
    });

    websocket.on('open', () => {
      logger.info("Connection established");
      stdinToWs(websocket);
      wsToStdout(websocket);
    });

    websocket.on('error', (error) => {
      logger.error(`WebSocket error: ${error.message}`);
    });

    websocket.on('close', (code, reason) => {
      logger.error(`Connection closed: ${code} - ${reason}`);
      process.exit(0);
    });
  } catch (e) {
    if (e instanceof Error) {
      logger.error(`Closing with error: ${e.message}`);
    } else {
      logger.error(`Closing with error: ${e}`);
    }
    process.exit(1);
  }
}

// Constants
const DATABUTTON_API_KEY = "DATABUTTON_API_KEY";

// Parse command line arguments
function parseArgs() {
  const args = {
    apikeyfile: '',
    verbose: false,
    debug: false,
    showUri: false,
    uri: '',
  };

  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    if (arg === '-k' || arg === '--apikeyfile') {
      args.apikeyfile = process.argv[++i];
    } else if (arg === '-v' || arg === '--verbose') {
      args.verbose = true;
    } else if (arg === '-d' || arg === '--debug') {
      args.debug = true;
    } else if (arg === '--show-uri') {
      args.showUri = true;
    } else if (arg === '-u' || arg === '--uri') {
      args.uri = process.argv[++i];
    } else if (arg === '-h' || arg === '--help') {
      showHelp();
      process.exit(0);
    }
  }

  return args;
}

function showHelp() {
  console.log("Usage: tsx databutton-app-mcp.ts [-h] [-k APIKEYFILE] [-v]");
  console.log("Expose Databutton app endpoints as LLM tools with MCP over websocket");
  console.log("");
  console.log("Options:");
  console.log("  -h, --help            Show this help message and exit");
  console.log("  -k, --apikeyfile      File containing the API key");
  console.log("  -v, --verbose         Run in verbose mode with info logging");
  console.log("  -d, --debug           Run in very verbose mode with debug logging");
  console.log("  --show-uri            Show URI it would connect to and exit");
  console.log("  -u, --uri             Use a custom URI for the MCP server endpoint");
  console.log("");
  console.log(`Instead of providing an API key filepath with -k, you can set the ${DATABUTTON_API_KEY} environment variable.`);
  console.log("");
  console.log("Go to https://databutton.com to build apps and get your API key.");
}

// Main function
async function main() {
  try {
    const args = parseArgs();
    const envApikey = process.env[DATABUTTON_API_KEY];

    const logLevel = args.debug ? 'debug' : (args.verbose ? 'info' : 'warning');
    
    // Configure log level
    if (logLevel === 'debug') {
      console.debug = console.debug || console.log;
    } else if (logLevel === 'info') {
      console.debug = () => {}; // Disable debug logs
    } else {
      console.debug = () => {}; // Disable debug logs
      console.info = () => {}; // Disable info logs
    }

    logger.info("Starting Databutton app MCP proxy");
    
    if (!(args.apikeyfile || envApikey)) {
      logger.error("No API key provided");
      process.exit(1);
    }

    let apikey: string;
    
    if (args.apikeyfile && await fs.stat(args.apikeyfile).catch(() => false)) {
      logger.info(`Using api key from file ${args.apikeyfile}`);
      apikey = (await fs.readFile(args.apikeyfile, 'utf8')).trim();
    } else {
      logger.info("Using api key from environment variable");
      apikey = envApikey || '';
    }

    if (!apikey) {
      logger.error("Provided API key is blank");
      process.exit(1);
    }

    const [uri, bearer] = await interpretApikey(apikey);
    
    let finalUri = uri;
    if (args.uri) {
      logger.info(`Using override uri from command line: ${args.uri}`);
      finalUri = args.uri;
    }

    if (args.showUri) {
      console.log("databutton-app-mcp would connect to:");
      console.log(finalUri);
      process.exit(0);
    }

    await runWsProxy(finalUri, bearer);
  } catch (e) {
    if (e instanceof Error) {
      logger.error(`Error: ${e.message}`);
    } else {
      logger.error(`Error: ${e}`);
    }
    process.exit(1);
  }
}

// Run main if this file is executed directly
if (require.main === module) {
  main().catch(e => {
    logger.error(`Unhandled error: ${e instanceof Error ? e.message : e}`);
    process.exit(1);
  });
}