const { randomUUID } = require('crypto');

function requestId(req, res, next) {
  const id = req.header('x-request-id') || randomUUID();
  req.requestId = id;
  res.setHeader('x-request-id', id);
  next();
}

module.exports = {
  requestId,
};
