FROM python:3-alpine3.15

WORKDIR /blog

COPY . /blog

RUN pip install -r requirements.txt

EXPOSE 5001

CMD ["flask", "run","--host","0.0.0.0"]