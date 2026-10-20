FROM python:3.12-slim
# nobody kullanıcısı syslog için 514'e bağlanabilsin (yalnız bu yetki)
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && setcap cap_net_bind_service=+ep "$(readlink -f /usr/local/bin/python3)" \
    && apt-get purge -y libcap2-bin && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY exporter.py .
USER nobody
EXPOSE 9877 514/udp
CMD ["python", "-u", "exporter.py"]
