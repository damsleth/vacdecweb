const { readFileSync, existsSync } = require('fs')
const { loadPemX509Certificate } = require('crypto').x509
const { base64Decode } = require('crypto').util
const { cosekeyFromJwkDict } = require('cryptography-js').cose
const os = require('os')
const sys = require('sys')
const zlib = require('zlib')
const argparse = require('argparse')
const logging = require('logging')
const { Image } = require('PIL')
const ImageFile = require('PIL').ImageFile
ImageFile.LOAD_TRUNCATED_IMAGES = true

const pyzbar = require('pyzbar.pyzbar')
const json = require('json')
const base45 = require('base45')
const base64 = require('base64')
const cbor2 = require('cbor2')
const cosekey = require('cose.keys')
const ec2 = require('cose.keys.ec2')
const keyops = require('cose.keys.keyops')
const keyparam = require('cose.keys.keyparam')
const curves = require('cose.keys.curves')
const keytype = require('cose.keys.keytype')
const cosemessage = require('cose.messages')
const algorithms = require('cose.headers').Algorithm
const KID = require('cose.headers').KID

const x509 = require('cryptography').x509
const hazmat = require('cryptography').hazmat
const asn1_decoder = require('pyasn1.codec.ber.decoder')
const cjwtk = require('cryptojwt.jwk')
const cjwt_utils = require('cryptojwt.utils')

log = logging.getLogger(__name__)

const DEFAULT_CERTIFICATE_DB_JSON = 'certs/roots/Digital_Green_Certificate_Signing_Keys.json'
const DEFAULT_CERTIFICATE_DIRECTORY = 'certs'

function _setup_logger() {
  const log_formatter = new logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
  const console_handler = new logging.StreamHandler()
  console_handler.setFormatter(log_formatter)
  console_handler.propagate = false
  const logger = logging.getLogger()
  logger.addHandler(console_handler)
  logger.setLevel(logging.INFO)
}


function find_key(key, keys_file) {
  let cose_key
  const key_id_str = key.toString('hex')
  const pem_filename = `${DEFAULT_CERTIFICATE_DIRECTORY}/${key_id_str}.pem`
  console.debug(`Check if certificate ${pem_filename} exists.`)
  if (existsSync(pem_filename)) {
    const lines = readFileSync(pem_filename)
    const cert = loadPemX509Certificate(lines)
    const subject = cert.subject
    if (subject) {
      const subject_parts = subject.map(subject_compo => `${subject_compo.oid._name} = ${subject_compo.value}`)
      console.debug(`Certificate subject: ${subject_parts.join(', ')}`)
    } else {
      console.debug('Certificate has no subject')
    }
    console.info(`Using certificate ${pem_filename}`)
    cose_key = _cert_to_cose_key(cert, key)
  } else {
    const known_keys = JSON.parse(readFileSync(keys_file, 'utf-8'))
    cose_key = null
    for (const [key_id, key_data] of Object.entries(known_keys)) {
      const key_id_binary = base64Decode(key_id)
      if (key_id_binary.equals(key)) {
        console.info('Found the key from DB!')
        const [x, y] = public_ec_key_points(base64Decode(key_data.publicKeyPem))
        const key_dict = {
          crv: key_data.publicKeyAlgorithm.namedCurve,
          kid: key_id_binary.toString('hex'),
          kty: key_data.publicKeyAlgorithm.name.slice(0, 2),
          x: x,
          y: y
        }
        cose_key = cosekeyFromJwkDict(key_dict)
        break
      }
    }
    if (!cose_key) {
      return null
    }
  }
  if (cose_key.kid.toString('hex') !== key.toString('hex')) {
    throw new Error(`Internal: No key for ${key.toString('hex')}!`)
  }
  return cose_key
}

function certToCoseKey(cert, key_id = null) {
  const public_key = cert.public_key()
  let key_dict = null

  if (public_key instanceof hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey) {
    const curve_name = public_key.curve.name
    let matching_curve = null
    for (const name in curves) {
      if (name.startsWith('_')) {
        continue
      }
      if (curve_name.toLowerCase() === name.toLowerCase()) {
        if (name === 'SECP256R1') {
          matching_curve = curves.P256
        } else if (name === 'SECP384R1') {
          matching_curve = curves.P384
        } else {
          throw new Error(`Unknown curve ${curve_name}!`)
        }
        break
      }
    }

    if (!matching_curve) {
      throw new Error(`Could not find curve ${curve_name} used in X.509 certificate from COSE!`)
    }

    const public_numbers = public_key.public_numbers()
    const size_bytes = public_key.curve.key_size / 8
    const x = public_numbers.x.to_bytes(size_bytes, "big")
    const y = public_numbers.y.to_bytes(size_bytes, "big")
    key_dict = {
      [keyparam.KpKeyOps]: [keyops.VerifyOp],
      [keyparam.KpKty]: keytype.KtyEC2,
      [keyparam.EC2KpCurve]: matching_curve,
      [keyparam.KpAlg]: algorithms.Es256,
      [keyparam.EC2KpX]: x,
      [keyparam.EC2KpY]: y,
      [keyparam.KpKid]: new Uint8Array(Buffer.from(key_id.hex(), "ASCII")),
    }
  } else {
    throw new Error("Cannot handle RSA-keys!")
  }

  const key = cosekey.CoseKey.from_dict(key_dict)

  return key
}

function public_ec_key_points(public_key) {
  // This code adapted from: https://stackoverflow.com/a/59537764/1548275
  const public_key_asn1 = asn1js.fromBER(public_key)
  const public_key_bytes = public_key_asn1.result.valueBlock.value[1].valueBlock.valueHex

  let off = 0
  if (public_key_bytes[off] !== 0x04) {
    throw new Error("EC public key is not an uncompressed point")
  }
  off += 1

  const size_bytes = (public_key_bytes.length - 1) / 2

  const x_bin = public_key_bytes.slice(off, off + size_bytes)
  const x = BigInt("0x" + Buffer.from(x_bin).toString("hex"))
  off += size_bytes

  const y_bin = public_key_bytes.slice(off, off + size_bytes)
  const y = BigInt("0x" + Buffer.from(y_bin).toString("hex"))
  off += size_bytes

  const x_buf = Buffer.from(x.toString(16).padStart(size_bytes * 2, "0"), "hex")
  const x_str = base64url.fromBase64(x_buf.toString("base64"))

  const y_buf = Buffer.from(y.toString(16).padStart(size_bytes * 2, "0"), "hex")
  const y_str = base64url.fromBase64(y_buf.toString("base64"))

  return [x_str, y_str]
}

function cosekey_from_jwk_dict(jwk_dict) {
  // Read key and return CoseKey
  if (jwk_dict["kty"] !== "EC") {
    throw new Error("Only EC keys supported")
  }
  if (jwk_dict["crv"] !== "P-256") {
    throw new Error("Only P-256 supported")
  }

  const x = base64url.decode(jwk_dict["x"])
  const y = base64url.decode(jwk_dict["y"])

  const key = new cosekey.EC2({
    crv: cosekey.curves.P_256,
    x: x,
    y: y,
  })

  key.key_ops = [cosekey.keyops.VerifyOp]

  if ("kid" in jwk_dict) {
    key.kid = Buffer.from(jwk_dict["kid"], "utf-8")
  }

  return key
}

async function read_cosekey_from_pem_file(cert_file) {
  if (!cert_file.endsWith(".pem")) {
    throw new Error("Unknown key format. Use .pem keyfile")
  }

  const cert_data = await fetch(cert_file).then(res => res.arrayBuffer())
  const cert = new jsrsasign.X509()
  cert.readCertPEM(Array.from(new Uint8Array(cert_data)).map(x => String.fromCharCode(x)).join(""))

  const sha256 = new jsrsasign.crypto.MessageDigest({ alg: "sha256", prov: "cryptojs" })
  sha256.updateHex(cert.getEncodedHex())
  const keyidentifier = sha256.digestHex().slice(0, 16)

  const key = KEYUTIL.getKey(cert.getPublicKey())

  const jwk = new KJUR.jws.JWS()
  jwk.initForVerifyByPublicKey(key, "ES256")
  jwk.parseJwk(jwk.generateJWK())

  jwk.kid = Buffer.from(keyidentifier, "hex").toString("utf-8").slice(0, 8)
  const jwk_dict = JSON.parse(jwk.parsedJWS.payloadS)

  return cosekey_from_jwk_dict(jwk_dict)
}


async function output_covid_cert_data(cert, keys_file) {
  const KID = 4

  // Strip the first characters to form valid Base45-encoded data
  const b45data = cert.substring(4)

  // Decode the data
  const zlibdata = base45.decode(b45data)

  // Uncompress the data
  const decompressed = pako.inflate(zlibdata)

  // Decode COSE message (no signature verification done)
  const cose_msg = CoseMessage.decode(decompressed)

  console.log(cose_msg.phdr)

  if (KID in cose_msg.phdr) {
    console.log("COVID certificate signed with X.509 certificate.")
    console.log("X.509 in DER form has SHA-256 beginning with: " + cose_msg.phdr[KID].toString('hex'))
    const key = await find_key(cose_msg.phdr[KID].toString('hex'), keys_file)
    if (key) {
      verify_signature(cose_msg, key)
    } else {
      console.log("Skip verify as no key found from database")
    }
  } else {
    console.log("Certificate is not signed")
  }

  const cbor = cbor.decode(cose_msg.payload)
  // Note: Some countries have hour:minute:secod for sc-field (Date/Time of Sample Collection).
  // If used, this will decode as a datetime. A datetime cannot be JSON-serialized without hints (use str as default).
  // Note 2: Names may contain non-ASCII characters in UTF-8
  console.log("Certificate as JSON: " + JSON.stringify(cbor, null, 2))
}

function verify_signature(cose_msg, key) {
  cose_msg.key = key
  if (!cose_msg.verify_signature()) {
    console.warn("Signature does not verify with key ID " + key.kid.toString())
    return false
  }

  console.log("Signature verified ok")

  return cose_msg.verify_signature()
}

function main() {
  const { createRequire } = require('module');
  const require = createRequire(import.meta.url);
  const argparse = require('argparse');
  const { decode } = require('jimp');
  const { decode: decodeQR } = require('jsqr');
  const { readFileSync } = require('fs');
  
  const parser = new argparse.ArgumentParser({
    description: 'EU COVID Vaccination Passport Verifier',
  });
  parser.add_argument('--image-file', {
    metavar: 'IMAGE-FILE',
    help: 'Image to read QR-code from',
  });
  parser.add_argument('--raw-string', {
    metavar: 'RAW-STRING',
    help: 'Contents of the QR-code as string',
  });
  parser.add_argument('image_file_positional', {
    metavar: 'IMAGE-FILE',
    nargs: '?',
    help: 'Image to read QR-code from',
  });
  parser.add_argument('--certificate-db-json-file', {
    default: DEFAULT_CERTIFICATE_DB_JSON,
    help: `Default: ${DEFAULT_CERTIFICATE_DB_JSON}`,
  });
  
  const args = parser.parse_args();
  _setup_logger();
  
  let covid_cert_data = null;
  let image_file = null;
  if (args.image_file_positional) {
    image_file = args.image_file_positional;
  } else if (args.image_file) {
    image_file = args.image_file;
  }
  
  if (image_file) {
    const image = await decode(readFileSync(image_file));
    const { data, width, height } = image.bitmap;
    const code = decodeQR(data, width, height);
    covid_cert_data = code.data;
  } else if (args.raw_string) {
    covid_cert_data = args.raw_string;
  } else {
    console.error('Input parameters: Need either --image-file or --raw-string QR-code content.');
    process.exit(2);
  }
  
  // Got the data, output
  console.debug(`Cert data: '${covid_cert_data}'`);
  output_covid_cert_data(covid_cert_data, args.certificate_db_json_file);
}


main()