# voting-HElib-script
[HeVote](https://github.com/HanBae/HeVote)에 사용할 [HElib](https://github.com/shaih/HElib)의 C++ 스크립트를 모아 놓은 Repsitory입니다.

## Usage
### preInstall
1. HElib을 clone하여 [INSTALL.txt]()의 설치 절차에 따라 설치합니다.
2. `HElib` 디렉토리를 해당 폴더 안에 넣으세요. 그러면 디렉토리 구조가 다음과 같은 모양이 될 것입니다.
```
voting-HElib-script
└── bin
    └── bin
    └── src
    └── test
    └── HElib
    └── ...
```

### compile
`src/` 디렉토리 안의 파일들을 컴파일하여 `bin/` 디렉토리에 실행파일을 생성합니다. 
```
make all
```

- `createKeys`: HElib의 비밀키와 공개키를 생성합니다.
- `encryptCandidateList`: HeVote에 사용할 후보들을 생성합니다.
- `tally`: HeVote에 사용합니다. 투표용지들의 덧셈 연산을 수행합니다.

### run
```
./bin/createKeys [params]
# or
./bin/encryptCandidateList [params]
# or
./bin/tally [params]
```

## examples
- createKeys
```
./bin/createKeys p=257 L=8 dir=data
```
- encryptCandidateList
```
./bin/encryptCandidateList v=0x9b3c2432639f060172725ad3be956ca171d88830 t=4 dir=data
```
- tally
```
./bin/tally n=4 dir=data 
```

## License
[MIT License](https://github.com/HanBae/voting-HElib-script/blob/master/LICENSE)
