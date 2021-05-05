

# when developing
cd into the build folder and run 
go build ../ && ./createKeys ansible signer uploadkeys --env dev


# to build binary
go build ./


##########################
old
##########################


# run tests

```
go test ./... -v
```

# example command

```
go run ./ create validators --bip39Seed "pipe model sustain file dwarf farm mass damp room decorate educate obtain alert oak cupboard soup flavor wheat naive dynamic bracket life waste clerk" --keystorePasswords testtest --bip39Password testtest --ForkVersion 0x00002009 --Count 3
```

# build

```
go build
```

# Clients and validators example

go run ../. validators add --name testclient -i ./clients/testclient/active

