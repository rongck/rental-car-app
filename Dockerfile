FROM python:3.9-slim
WORKDIR /app
RUN pip install --upgrade pip
COPY requirements.txt /app/
RUN pip install -r requirements
COPY . /app/
CMD [ "gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "--timeout", "30", "wsgi:app" ]