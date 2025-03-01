# FastAPI Async
- Backend: FastAPI
- Database: PostgreSQL
- Message Broker: Redis Pub/Sub

## Run Server
- Python 3.11+

### Install Packages
```shell
pip install -r src/requirements.txt
```

### Docker Compose
```shell
# run db & redis
docker compose up -d
docker compose down

# with servers
docker compose -f docker-compose.server.yml up -d
docker compose down --remove-orphans
```
### Run Migrations
```shell
alembic upgrade head
```
## Run Test
```shell
pytest
```

## Run load test
1. Sync / 10 Connections / 10s
   - wrk -c 10 -d 10 http://127.0.0.1:8000/sync/sleep
2. ASync / 10 Connections / 10s
   - wrk -c 10 -d 10 http://127.0.0.1:8000/async/sleep
3. Sync / 100 Connections / 10s
   - wrk -c 100 -d 10 http://127.0.0.1:8000/sync/sleep
4. ASync / 100 Connections / 10s
   - wrk -c 100 -d 10 http://127.0.0.1:8000/async/sleep
 * If the above command doesn't work, try running it using Docker:
```shell
docker run --rm williamyeh/wrk -c 10 -d 10 http://host.docker.internal:8000/sync/sleep
```
