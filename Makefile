install :
	#${INFO} "Windows/amd64"
	GOOS=windows GOARCH=amd64 go install .
	#${INFO} "linux/amd64"
	GOOS=linux GOARCH=amd64 go install .
	#${INFO} "linux/arm64"
	GOOS=linux GOARCH=arm64 go install . 