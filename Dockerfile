FROM golang:latest
WORKDIR /go/src/content-blocker
COPY . .
RUN go get -v /go/src/content-blocker
RUN go build /go/src/content-blocker
CMD ["content-blocker -update -validation"]
