OSNAME=$(shell uname -s)

buildbaserun:
	echo "building base..."
	docker build -t botblocker .
	docker stop botblocker | true
	docker rm botblocker | true
	docker run -d --name botblocker botblocker

build:
	echo "building exe..."
ifeq ($(OSNAME),Linux)
	dart2native bin/bb.dart
else
	make buildbaserun
	docker exec botblocker dart2native /app/bin/bb.dart
	docker cp botblocker:/app/bin/bb.exe ./bin/bb.exe
endif

