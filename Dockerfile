FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md requirements.txt ./
COPY sentinel_x ./sentinel_x
RUN pip install --no-cache-dir .
ENV SENTINEL_X_HOME=/data/cases
VOLUME ["/data", "/evidence"]
ENTRYPOINT ["sentinel-x"]
CMD ["--help"]
