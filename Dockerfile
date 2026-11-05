FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
RUN groupadd --gid 10001 gateway && useradd --uid 10001 --gid gateway --no-create-home gateway
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER 10001:10001
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import os, urllib.request; h=os.environ.get('LISTEN_HOST','0.0.0.0'); h='127.0.0.1' if h=='0.0.0.0' else ('::1' if h=='::' else h); h='['+h+']' if ':' in h else h; urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://'+h+':'+os.environ.get('LISTEN_PORT','8765')+'/healthz',timeout=3).read()"
CMD ["python", "app.py"]
