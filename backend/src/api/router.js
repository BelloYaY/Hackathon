const express = require('express');

const { tenantRouter } = require('./tenantRoutes');
const { authRouter } = require('./authRoutes');
const { deviceRouter } = require('./deviceRoutes');
const { tokenRouter } = require('./tokenRoutes');
const { sessionRouter } = require('./sessionRoutes');
const { trustRouter } = require('./trustRoutes');
const { policyRouter } = require('./policyRoutes');
const { vaultRouter } = require('./vaultRoutes');
const { auditRouter } = require('./auditRoutes');
const { monitorRouter } = require('./monitorRoutes');

const apiRouter = express.Router();

apiRouter.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'lucentid-core' });
});

apiRouter.use('/tenant', tenantRouter);
apiRouter.use('/auth', authRouter);
apiRouter.use('/device', deviceRouter);
apiRouter.use('/token', tokenRouter);
apiRouter.use('/session', sessionRouter);
apiRouter.use('/trust', trustRouter);
apiRouter.use('/policy', policyRouter);
apiRouter.use('/vault', vaultRouter);
apiRouter.use('/audit', auditRouter);
apiRouter.use('/monitor', monitorRouter);

module.exports = {
  apiRouter,
};
