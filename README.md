# Bitcoin peers.dat Reader

This library was inspired by [this](https://raghavsood.com/blog/2018/05/20/demystifying-peers-dat), which uses a library written in Go.

I rewrote it in Python and also extracted parts of `peers.dat` that Go version was skipping - bucket data.

Usage:

```
git clone git@github.com:asood123/bitpeers.git
pip install -r requirements.txt
python bitpeers.py --file=sample_peers.dat --output=json
```
