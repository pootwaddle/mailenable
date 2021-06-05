cd fileparse
go get -u github.com/pootwaddle/mailenable/scrubbing@latest
go mod tidy
go build
copy *.exe \\moe\d\bjtools\ /Y
cd ..\greysplit
go get -u github.com/pootwaddle/mailenable/scrubbing@latest
go mod tidy
go build
copy *.exe \\moe\d\bjtools\ /Y
cd ..\logparse
go get -u github.com/pootwaddle/mailenable/scrubbing@351ee46e61bdd27008bcfea5bf060711abab44bc
go mod tidy
go build
copy *.exe \\moe\d\bjtools\ /Y
cd ..\malbytes
go get -u github.com/pootwaddle/mailenable/scrubbing@351ee46e61bdd27008bcfea5bf060711abab44bc
go mod tidy
go build
copy *.exe \\moe\d\bjtools\ /Y
cd ..\cleanit
go get -u github.com/pootwaddle/mailenable/scrubbing@351ee46e61bdd27008bcfea5bf060711abab44bc
go mod tidy
go build
copy *.exe \\moe\d\bjtools\ /Y
cd ..\greyparse
go get -u github.com/pootwaddle/mailenable/scrubbing@351ee46e61bdd27008bcfea5bf060711abab44bc
go mod tidy
go build
copy *.exe \\moe\d\bjtools\ /Y
cd ..\spamparse
go get -u github.com/pootwaddle/mailenable/scrubbing@351ee46e61bdd27008bcfea5bf060711abab44bc
go mod tidy
go build
copy *.exe \\moe\d\bjtools\ /Y
cd ..
