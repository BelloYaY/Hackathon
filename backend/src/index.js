const { createApp } = require('./app');
const { settings } = require('./config/settings');

const app = createApp();

app.listen(settings.port, () => {
  console.log(`${settings.appName} listening on port ${settings.port}`);
});
