
## DB

ルート権限
```
mysql -u root -p
```

SELECT, INSERT, UPDAT権限
```
mysql -D snippetbox -u web -p
```

## Test

webサーバー
```
go test -v ./cmd/web/
```

all
```
go test -v -short ./...
```