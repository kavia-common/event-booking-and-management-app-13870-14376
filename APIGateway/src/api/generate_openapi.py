import json
import os
from pathlib import Path

from src.api.main import app

# Generate API Gateway schema
openapi_schema = app.openapi()

output_dir = "interfaces"
os.makedirs(output_dir, exist_ok=True)
output_path = os.path.join(output_dir, "openapi.json")

with open(output_path, "w") as f:
    json.dump(openapi_schema, f, indent=2)

# Copy discovered upstream specs into the gateway interfaces dir for centralized discovery
# These paths are based on repository structure provided in task.
mapping = {
    "../../event-booking-and-management-app-13870-14377/UserService/interfaces/openapi.json": "UserService.openapi.json",
    "../../event-booking-and-management-app-13870-14379/BookingService/interfaces/openapi.json": "BookingService.openapi.json",
    "../../event-booking-and-management-app-13870-14380/VenueService/interfaces/openapi.json": "VenueService.openapi.json",
    "../../event-booking-and-management-app-13870-14381/NotificationService/interfaces/openapi.json": "NotificationService.openapi.json",
}
for src_rel, dest_name in mapping.items():
    src = Path(__file__).resolve().parent / src_rel
    dest = Path(output_dir) / dest_name
    try:
        with open(src, "r") as sf, open(dest, "w") as df:
            df.write(sf.read())
    except Exception as exc:
        # Do not fail generation if an upstream is missing; note with a stub file.
        with open(dest, "w") as df:
            df.write(json.dumps({"warning": f"Could not copy upstream spec from {src}", "error": str(exc)}, indent=2))
