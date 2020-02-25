const axios = require("axios");
const _ = require("lodash");
const chalk = require("chalk");
const fs = require("fs");
const path = require("path");
const {
  encrypt,
  debug,
  decrypt,
  encryptStringWithRsaPublicKey,
  decryptStringWithRsaPrivateKey,
  Logger
} = require("./utils");
const {
  publicKey,
  privateKey,
  transactionId,
  accessToken,
  kioskId
} = require("./utils/secret");

async function main() {
  Logger("Main Start");
  Logger("Transaction Id", transactionId);

  const res = await axios({
    url: `http://web-service.localhost.com/api/v1/k/transactions/${transactionId}`,
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  })
    .then(r => r.data)
    .catch(e => console.log(chalk.white.bgRed(e)));

  Logger("Response Key", res.result.key);

  const private_key = fs.readFileSync(
    path.join(__dirname, "./private.pem"),
    "utf-8"
  );

  const key = decryptStringWithRsaPrivateKey(
    res.result.key,
    private_key,
    kioskId
  );

  Logger("Decrypted Key ", key);

  Logger("Response Data", res.result.data);

  Logger("Decrypted Data");

  debug(JSON.parse(decrypt(res.result.data, key)));
}

main();
