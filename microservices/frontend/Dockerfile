FROM python:3.11-alpine
COPY requirements.txt /
RUN pip install -r /requirements.txt
COPY . /app
WORKDIR /app
EXPOSE 80
CMD [ "python", "frontend.py" ]