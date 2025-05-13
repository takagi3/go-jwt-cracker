# go-jwt-cracker
Concurrent HS256 JWT token brute force cracker, inspired by https://github.com/lmammino/jwt-cracker

This tool is realistically only effective to crack JWTs with weak secrets. It currently only supports HMAC-SHA256 (HS256) signatures.

It uses a worker pool (default: number of CPU cores) for efficient parallel brute-forcing. Progress, hash rate, and estimated time remaining (ETA) are displayed in real time.

Feel free to create a pull request with an improvement or fix :smile:

## Usage
```
Usage of go-jwt-cracker:
  -alphabet string
        The alphabet to use for the brute force (default "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
  -maxlen int
        The max length of the string generated during the brute force (default 12)
  -prefix string
        A string that is always prefixed to the secret
  -suffix string
        A string that is always suffixed to the secret
  -token string
        The full HS256 jwt token to crack
  -workers int
        Number of worker goroutines (default: number of CPU cores)
```

## Example
Cracking a token generated with [jwt.io](https://jwt.io):

```bash
go-jwt-cracker -token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o" -alphabet "abcdefghijklmnopqrstuwxyz" -maxlen 6
```

### Output

```
Parsed JWT:
- Algorithm: HS256
- Type: JWT
- Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
- Signature (hex): 5db3df6c81cc23a6ab67763ddb60618d6810cd65dc5cdaf3d2882d5617c4776a

There are 254313150 combinations to attempt
Cracking JWT secret...
[==================              ]  50% (127156575/254313150) 1234567 hashes/sec ETA: 0h01m23s
[===================             ]  55% (139872232/254313150) 1240000 hashes/sec ETA: 0h01m00s
...

Found secret in 184776821 attempts: secret
```

- The right side of the progress bar shows the number of hashes per second (hashes/sec) and the estimated time remaining (ETA).
- The number of workers defaults to the number of CPU cores, but can be changed with the `-workers` option.