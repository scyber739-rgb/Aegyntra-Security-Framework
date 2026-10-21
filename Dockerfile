FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN addgroup --system aegyntra && adduser --system --ingroup aegyntra aegyntra
COPY pyproject.toml README.md ./
COPY aegyntra ./aegyntra
COPY dashboard ./dashboard
RUN pip install --no-cache-dir . && mkdir -p /app/data && chown -R aegyntra:aegyntra /app
USER aegyntra
EXPOSE 8010
CMD ["uvicorn","aegyntra.platform:app","--host","0.0.0.0","--port","8010"]
