#!/bin/sh

# TimeZone validation
if [ -z "${TZ}" ] ; 
then 
    echo "Please set TZ environment variable with -e TZ=(timezone)"
    echo ""
else
    echo ${TZ} > /etc/timezone
    echo ""
    echo "Timezone is $(cat /etc/timezone)"
fi

echo "CRON is $CRON"
echo "$CRON /app/update" > /etc/crontabs/root

# Ensure crontab permissions and newline
chmod 0644 /etc/crontabs/root || true
echo "Starting crond (logging to stdout)..."
# Start crond in foreground but background it so we can exec the main process.
# Use /proc/1/fd/1 so logs appear in container logs (Docker/RouterOS container stdout).
# -f runs in foreground; backgrounding with & keeps it running while we exec the main process.
/usr/sbin/crond -f -L /proc/1/fd/1 &

# Give crond a moment to load the crontab
sleep 1

exec "$@"
