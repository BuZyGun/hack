FROM python:3.11-alpine
COPY requirements.txt /
RUN pip install -r /requirements.txt
COPY . /app
WORKDIR /app
EXPOSE 5000
CMD [ "python", "app.py" ]