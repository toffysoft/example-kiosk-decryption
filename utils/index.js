const crypto = require("crypto");

const chalk = require("chalk");

const generateKeyPairSync = crypto.generateKeyPairSync;

const debug = data => {
  console.log(chalk.white.bgRed(JSON.stringify(data)));
};

exports.Logger = (title = "", detail = "") => {
  console.log(
    `${chalk.white.bgMagenta(`${title} => `)}${chalk.white.bgBlue(detail)}`
  );
  console.log();
};

exports.debug = debug;

function getSecret(secret) {
  const hash = crypto.createHash("sha256");
  hash.update(secret);

  return hash.digest("hex").substring(0, 32);
}

function encrypt(text, secret) {
  let iv = crypto.randomBytes(16);
  let cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(getSecret(secret)),
    iv
  );
  let encrypted = cipher.update(text);

  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decrypt(text, secret) {
  let textParts = text.split(":");
  let iv = Buffer.from(textParts.shift(), "hex");
  let encryptedText = Buffer.from(textParts.join(":"), "hex");
  let decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(getSecret(secret)),
    iv
  );
  let decrypted = decipher.update(encryptedText);

  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString();
}

function encryptStringWithRsaPublicKey(toEncrypt, publicKey) {
  const buffer = Buffer.from(toEncrypt);
  const encrypted = crypto.publicEncrypt(publicKey, buffer);
  return encrypted.toString("base64");
}

function decryptStringWithRsaPrivateKey(
  toDecrypt,
  privateKey,
  passphrase = ""
) {
  const buffer = Buffer.from(toDecrypt, "base64");

  const decrypted = crypto.privateDecrypt(
    {
      key: privateKey,
      passphrase
    },
    buffer
  );
  return decrypted.toString("utf8");
}

exports.getKeyPair = function(passphrase = "") {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: "spki",
      format: "pem"
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: passphrase
    }
  });

  return {
    publicKey,
    privateKey,
    passphrase
  };
};

exports.encryptStringWithRsaPublicKey = encryptStringWithRsaPublicKey;
exports.decryptStringWithRsaPrivateKey = decryptStringWithRsaPrivateKey;
exports.encrypt = encrypt;
exports.decrypt = decrypt;

exports.getSecret = getSecret;
