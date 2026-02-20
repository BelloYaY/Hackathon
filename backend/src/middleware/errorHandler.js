function errorHandler(err, _req, res, _next) {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal server error';
  if (statusCode >= 500) {
    console.error(err);
  }
  res.status(statusCode).json({ detail: message });
}

module.exports = {
  errorHandler,
};
