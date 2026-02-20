const express = require('express');

const { apiRouter } = require('./api/router');
const { requestId } = require('./middleware/requestId');
const { cors } = require('./middleware/cors');
const { securityHeaders } = require('./middleware/securityHeaders');
const { rateLimit } = require('./middleware/rateLimit');
const { errorHandler } = require('./middleware/errorHandler');

function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));
  app.use(requestId);
  app.use(cors);
  app.use(securityHeaders);
  app.use(rateLimit({ windowMs: 60_000, max: 600 }));

  app.use('/api/v1', apiRouter);

  app.use(errorHandler);

  return app;
}

module.exports = {
  createApp,
};
