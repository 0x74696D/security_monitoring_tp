import logging
import sys
from flask import Flask, request
import os

app = Flask(__name__)

# -------------------------
# Logging configuration
# -------------------------
logger = logging.getLogger("vulnerable-app")
logger.setLevel(logging.DEBUG)

# Log to STDOUT
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)

# Log to STDERR
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.ERROR)

# Format logs
formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s"
)
stdout_handler.setFormatter(formatter)
stderr_handler.setFormatter(formatter)

logger.addHandler(stdout_handler)
logger.addHandler(stderr_handler)


@app.route("/")
def index():
    logger.info("Received request on '/' endpoint")
    return "Hello from a vulnerable container!"


@app.route("/debug")
def debug():
    cmd = request.args.get("cmd", "id")
    logger.warning(f"/debug endpoint called with cmd='{cmd}'")
    
    try:
        output = os.popen(cmd).read()
        logger.debug(f"Command output: {output}")
        return output
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        return "Error", 500


if __name__ == "__main__":
    logger.info("Starting vulnerable Flask app on port 8080...")
    app.run(host="0.0.0.0", port=8080)