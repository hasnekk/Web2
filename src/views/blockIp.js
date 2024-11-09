// Middleware to check if the IP is blocked
function checkIPBlock(req, res) {
  const ip = req.ip; // Get IP from the request
  if (failedAttempts[ip] && failedAttempts[ip].blockedUntil > Date.now()) {
    // If the IP is blocked, return a message
    return res
      .status(403)
      .send(
        'Your IP is blocked due to too many failed login attempts. Try again later.'
      );
  }
}
