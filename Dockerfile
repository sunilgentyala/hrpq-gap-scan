FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --uid 1000 --create-home scanner
USER scanner

ENTRYPOINT ["hrpq-gap-scan"]
CMD ["--help"]
