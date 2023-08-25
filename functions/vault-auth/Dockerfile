FROM fnproject/go:1.19-dev as build-stage

COPY . /func
RUN ls -aFl /func/
WORKDIR /func
RUN go build -o func

FROM fnproject/go:1.19
WORKDIR /function
COPY --from=build-stage /func/func /function/
ENTRYPOINT ["./func"]
