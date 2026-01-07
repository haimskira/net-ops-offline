FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
COPY requirements.txt .
COPY offline-pack/ ./offline-pack/
RUN pip install --no-cache-dir --no-index --find-links=./offline-pack/ -r requirements.txt
COPY . .

# הסרת תיקיית החבילות לאחר ההתקנה להקטנת נפח האימג'
# RUN rm -rf ./offline-pack

# Expose the application port
EXPOSE 5100
EXPOSE 514/udp

# Run the application
CMD ["python", "app.py"]