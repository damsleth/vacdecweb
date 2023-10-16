#!/usr/bin/env node

const fs = require("fs");
const zlib = require("zlib");
const argparse = require("argparse");
const sharp = require("sharp");
const jsQR = require("jsqr");
const cose = require("cose-js");
const base45 = require("base45-js");
const base64url = require("base64url");
const cbor = require("cbor");

const {
  KeyOps,
  CoseKey,
  EdDSA,
  OKP,
  RSA,
  EC2,
  KpKty,
  KpAlg,
  KpKid,
  KpCurve,
  EllipticCurves,
  KeyType,
  X25519,
  X448,
  Ed25519,
  Ed448,
} = require("cose-js/lib/index");

const {
  Certificate,
  SHA256,
  verify,
  derToJose,
  JOSEHeader,
} = require("jsrsasign");

const { decode: decodePEM } = require("pem");

const DEFAULT_CERTIFICATE_DB_JSON =
  "certs/roots/Digital_Green_Certificate_Signing_Keys.json";
const DEFAULT_CERTIFICATE_DIRECTORY = "certs";

function setupLogger() {
  const logFormatter = new Intl.DateTimeFormat(undefined, {
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  const consoleHandler = new console.Console({
    stdout: process.stdout,
    stderr: process.stderr,
    format: (args) =>
      `[${logFormatter.format(new Date())}] [${args.level}]  ${args.message}`,
  });

  consoleHandler.propagate = false;
  consoleHandler.level = "info";
}

function findKey(key, keysFile) {
  const keyIdStr = Buffer.from(key).toString("hex");
  const pemFilename = `${DEFAULT_CERTIFICATE_DIRECTORY}/${keyIdStr}.pem`;

  console.log(`Check if certificate ${pemFilename} exists.`);

  if (fs.existsSync(pemFilename)) {
    const pemData = fs.readFileSync(pemFilename);
    const cert = new Certificate(pemData);

    try {
      const subject = cert.getSubjectString();
      console.log(`Certificate subject: ${subject}`);
    } catch (err) {
      console.log("Certificate has no subject");
    }

    console.log(`Using certificate ${pemFilename}`);
    const coseKey = certToCoseKey(cert, key);
    return coseKey;
  }

  // Read the JSON-database of all known keys
  const knownKeys = JSON.parse(fs.readFileSync(keysFile, "utf-8"));

  let coseKey = null;
  for (const keyIdBase64 in knownKeys) {
    const keyIdBinary = base64url.toBuffer(keyIdBase64);

    if (keyIdBinary.equals(key)) {
      console.log("Found the key from DB!");
      const keyData = knownKeys[keyIdBase64];

      // Check if the point is uncompressed rather than compressed
      const { x, y } = publicEcKeyPoints(
        base64url.toBuffer(keyData.publicKeyPem)
      );

      const keyDict = {
        [KpKty]: KeyType.EC2,
        [KpCurve]: EllipticCurves.P256,
        [KpAlg]: EdDSA,
        x,
        y,
        [KpKid]: keyIdBinary.toString("hex"),
      };

      coseKey = coseKeyFromJwkDict(keyDict);
      break;
    }
  }

  if (!coseKey) {
    return null;
  }

  if (coseKey.get(KpKid) !== key.toString("hex")) {
    throw new Error(`Internal: No key for ${key.toString("hex")}!`);
  }

  return coseKey;
}

function certToCoseKey(cert, keyId = null) {
  const publicKey = cert.getPublicKey();
  let keyDict = null;

  if (publicKey.type === "ec") {
    const curveName = publicKey.asymmetricCurve;
    let matchingCurve = null;

    for (const curve in EllipticCurves) {
      if (EllipticCurves[curve] === curveName) {
        matchingCurve = EllipticCurves[curve];
        break;
      }
    }

    if (!matchingCurve) {
      throw new Error(`Unknown curve ${curveName}!`);
    }

    const publicNumbers = publicKey.publicNumbers();
    const sizeBytes = publicKey.n.byteLength;
    const x = Buffer.alloc(sizeBytes);
    publicNumbers.x.toBuffer().copy(x);
    const y = Buffer.alloc(sizeBytes);
    publicNumbers.y.toBuffer().copy(y);

    keyDict = {
      [KpKty]: KeyType.EC2,
      [KpCurve]: matchingCurve,
      [KpAlg]: EdDSA,
      x,
      y,
      [KpKid]: keyId ? Buffer.from(keyId.toString(), "hex") : null,
    };
  } else {
    throw new Error("Cannot handle RSA keys!");
  }

  const coseKey = CoseKey.fromObject(keyDict);
  return coseKey;
}

function publicEcKeyPoints(publicKey) {
  // This code adapted from: https://stackoverflow.com/a/59537764/1548275
  const publicNumbers = asn1decode(publicKey)[1].value[0].value;
  const sizeBytes = publicKey.length - 1;

  let off = 1;
  if (publicKey[off] !== 0x04) {
    throw new Error("EC public key is not an uncompressed point");
  }
  off++;

  const xBin = publicKey.slice(off, off + sizeBytes);
  off += sizeBytes;

  const yBin = publicKey.slice(off, off + sizeBytes);

  const x = base64url.encode(xBin);
  const y = base64url.encode(yBin);

  return { x, y };
}

function coseKeyFromJwkDict(jwkDict) {
  if (jwkDict.kty !== "EC") {
    throw new Error("Only EC keys supported");
  }

  if (jwkDict.crv !== "P-256") {
    throw new Error("Only P-256 supported");
  }

  const key = new EC2({
    [KpCurve]: EllipticCurves.P256,
    x: Buffer.from(jwkDict.x, "base64"),
    y: Buffer.from(jwkDict.y, "base64"),
  });

  key.key_ops = [KeyOps.VerifyOp];

  if (jwkDict.kid) {
    key.set(KpKid, Buffer.from(jwkDict.kid, "hex"));
  }

  return key;
}

function coseKeyFromPEMFile(certFile) {
  if (!certFile.endsWith(".pem")) {
    throw new Error("Unknown key format. Use .pem keyfile");
  }

  const pemData = fs.readFileSync(certFile);
  const cert = new Certificate(pemData);

  // Calculate Hash from the DER format of the Certificate
  const keyIdentifier = Buffer.from(cert.fingerprint(SHA256), "hex");
  const key = cert.getPublicKey();

  const jwk = new Key();

  jwk.loadKey(key);

  // Use first 8 bytes of the hash as Key Identifier (Hex as UTF-8)
  jwk.set(KpKid, keyIdentifier.slice(0, 8).toString("hex"));

  const jwkDict = jwk.serialize(false);

  return coseKeyFromJwkDict(jwkDict);
}

function outputCovidCertData(cert, keysFile) {
  // Code adapted from: https://alphalist.com/blog/the-use-of-blockchain-for-verification-eu-vaccines-passport-program-and-more

  // Strip the first characters to form valid Base45-encoded data
  const b45Data = cert.slice(4);

  // Decode the data
  const zlibData = base45.decode(b45Data);

  // Uncompress the data
  const decompressed = zlib.inflateSync(zlibData);

  // Decode COSE message (no signature verification done)
  const coseMsg = CoseKey.decode(decompressed);

  if (KpKid in coseMsg.phdr) {
    console.log("COVID certificate signed with X.509 certificate.");
    console.log(
      `X.509 in DER form has SHA-256 beginning with: ${coseMsg.phdr[
        KpKid
      ].toString("hex")}`
    );

    const key = findKey(coseMsg.phdr[KpKid], keysFile);

    if (key) {
      verifySignature(coseMsg, key);
    } else {
      console.log("Skip verify as no key found from database");
    }
  } else {
    console.log("Certificate is not signed");
  }

  const cborData = cbor.decode(coseMsg.payload);
  console.log(`Certificate as JSON: ${JSON.stringify(cborData, null, 2)}`);
}

function verifySignature(coseMsg, key) {
  coseMsg.key = key;

  if (!coseMsg.verifySignature()) {
    console.log(
      `Signature does not verify with key ID ${key.get(KpKid).toString("hex")}!`
    );
    return false;
  }

  console.log("Signature verified ok");
  return true;
}

async function main() {
  setupLogger();

  const parser = new argparse.ArgumentParser({
    description: "EU COVID Vaccination Passport Verifier",
  });

  parser.add_argument("--image-file", {
    metavar: "IMAGE-FILE",
    help: "Image to read QR-code from",
  });

  parser.add_argument("--raw-string", {
    metavar: "RAW-STRING",
    help: "Contents of the QR-code as string",
  });

  parser.add_argument("image_file_positional", {
    metavar: "IMAGE-FILE",
    nargs: "?",
    help: "Image to read QR-code from",
  });

  parser.add_argument("--certificate-db-json-file", {
    default: DEFAULT_CERTIFICATE_DB_JSON,
    help: `Default: ${DEFAULT_CERTIFICATE_DB_JSON}`,
  });

  const args = parser.parse_args();

  let covidCertData = null;
  let imageFile = null;

  if (args.image_file_positional) {
    imageFile = args.image_file_positional;
  } else if (args.image_file) {
    imageFile = args.image_file;
  }

  if (imageFile) {
    const imageBuffer = fs.readFileSync(imageFile);
    const { data, width, height } = sharp(imageBuffer)
      .raw()
      .toBuffer({ resolveWithObject: true });

    const code = jsQR(data, width, height);
    if (code) {
      covidCertData = code.data;
    }
  } else if (args.raw_string) {
    covidCertData = args.raw_string;
  } else {
    console.error(
      "Input parameters: Need either --image-file or --raw-string QR-code content."
    );
    process.exit(2);
  }

  console.log(`Cert data: '${covidCertData}'`);
  outputCovidCertData(covidCertData, args.certificate_db_json_file);
}

if (require.main === module) {
  main();
}
