cd %1
go clean -modcache -r
go get -u -v github.com/pootwaddle/scrubbing@v0.2
go mod tidy
go build
copy *.exe \\moe\d\bjtools\ /Y
cd ..
