FROM python:3.12-alpine
WORKDIR /app
COPY server.py .
COPY www ./www
EXPOSE 3000
CMD ["python", "server.py"]
