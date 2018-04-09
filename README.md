# inet-archaeo
inet-archaeo collects network configuration info. via SNMP and output in JSON format.
Generated JSON file can be used to draw network diagram by [inet-henge](https://github.com/codeout/inet-henge)

## Getting Started

You can setup like below:

```
git clone https://github.com/atfujiwara/inet-archaeo.git
cd inet-archaeo
pip install -r requirements.txt
```

After that, copy the sample config file and modify as you like.

```
cp sample_config.yaml your_config.yaml
vi your_config.yaml
# add nodes, icons, rules etc
```

Finally, execute `inet-archaeo.py`. JSON data is printed to STDOUT by default. So you need to redirect to a file to use it with inet-henge.

```
./inet-archaeo.py -c your_config.yaml > diagram.json
```

## Copyright and License

Copyright (c) 2018 Atsushi Fujiwara. Code released under the [MIT license](LICENSE).
