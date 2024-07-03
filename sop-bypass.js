// Exploit CORS in any browser, bypass SOP using Google Cloud Functions. On demand HTTPS Proxy, masquerade Google IP

const functions = require('firebase-functions');
const cors = require('cors')({ origin: true });
const fetch = require('node-fetch');

const whitelistHeaders = [
  'accept-encoding',
  'accept-language',
  'authorization',
  'content-security-policy',
  'content-type',
  'referrer-policy',
  'x-frame-options'
];

const getBaseUrl = (request) => !request.query.url ? request.body.url : request.query.url
const createRequest = ({baseUrl, req, headersFilter, urlDecorator}) => {
  const request = {};

  if (req.method === "POST" || req.method === "PUT") {
    req.get("content-type") === "application/json"
      ? (request.body = JSON.stringify(req.body))
      : (request.body = req.body);
  }

  request.url = urlDecorator(baseUrl, req.query)
  request.method = req.method;
  request.headers = headersFilter(req.headers)

  return request;
}

const urlDecorator = (baseUrl, requestQuery) => {
  let finalUrl = baseUrl
  if(!baseUrl.startsWith('http')) finalUrl = "https://" + finalUrl
  Object.keys(requestQuery).map(item => {
    if (item !== 'url') {
      finalUrl += `&${item}=${decodeURI(requestQuery[item])}`;
    }
  });
  return finalUrl;
}

const stripHeaders = (requestHeaders, whiteListHeaders) => {
  return Object.keys(requestHeaders)
    .filter(key => whiteListHeaders.includes(key))
    .reduce((obj, key) => {
      obj[key] = requestHeaders[key];
      return obj;
    }, {})
}

exports.cors = functions.https.onRequest((req, res) => {
  const headersFilter = (headers) => stripHeaders(headers, whitelistHeaders)

  cors(req, res, async () => {
    const baseUrl = getBaseUrl(req)

    if (!baseUrl) {
      res.status(403).send('Endpoint URL not specified.');
      return
    }

    const forwardRequest = createRequest({
      req,
      baseUrl,
      headersFilter,
      urlDecorator
    })

    return fetch(forwardRequest.url, forwardRequest).then(r => {
      r.body.on('data', chunk => {
        res.write(chunk);
      });

      return new Promise(resolve => {
        r.body.on('end', () => {
          resolve(res.end(null));
        });
      });
    });
  });
});
