# SafetyNet validator

## Usage
Given a [SafetyNet Attestation](https://developer.android.com/training/safetynet/attestation#transfer-response-to-server) 

```go
attestation, err := safetynet.ValidateNew(safetynetJws)
```

The token is then validated and returned as `attestation`.

## License

TBD
