## pip install pytz
from datetime import datetime
import time
import pytz

# Get current time in epoch (UTC)
current_epoch = int(datetime.now(pytz.UTC).timestamp())
current_epoch_ms = current_epoch * 1000

# Convert epoch to datetime (explicitly using UTC)
dt_utc = datetime.fromtimestamp(current_epoch, tz=pytz.UTC)
dt_local = datetime.fromtimestamp(current_epoch, tz=pytz.UTC)

# Get UTC timezone name
utc_tz = pytz.UTC

print(f"Current Epoch timestamp: {current_epoch}")
print(f"Current Epoch Timestamp in milliseconds: {current_epoch_ms}")
print(f"Date and time (GMT): {dt_utc.strftime('%A, %B %d, %Y %I:%M:%S %p')} GMT")
print(f"Date and time (GMT): {dt_local.strftime('%A, %B %d, %Y %I:%M:%S %p')} GMT")
print()

# JWT-style timestamps (all times in GMT/UTC)
print("For https://jwt.io/ . Expiry set to +5 minutes from now")
print("-------------------")
print(f'"exp": {current_epoch + (5 * 60)},')  # Add 5 minutes to expiration
print(f'"nbf": {current_epoch},')             # Current GMT time
print(f'"iat": {current_epoch}')              # Current GMT time