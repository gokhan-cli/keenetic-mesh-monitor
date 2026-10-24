FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY exporter.py .
USER nobody
EXPOSE 9877
CMD ["python", "-u", "exporter.py"]
