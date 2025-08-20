FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-rss-connector

# Install system dependencies
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Install Python modules
RUN cd /opt/opencti-rss-connector && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del build-base

# Create log directory and set permissions
RUN mkdir -p /opt/opencti-rss-connector/logs && \
    touch /opt/opencti-rss-connector/connector.log && \
    chmod 666 /opt/opencti-rss-connector/connector.log

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
