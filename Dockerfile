FROM python:3.12-slim
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m appuser
WORKDIR /app
COPY --chown=appuser:appuser app/ .
RUN pip install --no-cache-dir -r requirements.txt && chown appuser:appuser /app
USER appuser
ENV HOST=0.0.0.0
EXPOSE 5000
CMD ["python", "app.py"]
