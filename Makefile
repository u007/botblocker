
buildbaserun:
	echo "building base..."
	docker build -t botblocker .
	docker stop botblocker | true
	docker rm botblocker | true
	docker run -d --name botblocker botblocker

build: buildbaserun
	echo "building exe..."
	docker exec botblocker dart2native /app/bin/bb.dart
	docker cp botblocker:/app/bin/bb.exe ./bin/bb.exe
