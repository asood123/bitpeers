# Bitcoin peers.dat Reader

You can use this library to dump your `peers.dat` file from your Bitcoin client. This file keeps track of all your peers and what buckets they are currently in.

I was inspired by [a blogpost](https://raghavsood.com/blog/2018/05/20/demystifying-peers-dat), whose author wrote a similar library in Go.

I rewrote it in Python and also extracted parts of `peers.dat` that the Go-version was skipping, mainly bucket data.

Usage:

```
git clone https://github.com/asood123/bitpeers.git
pip install -r requirements.txt
python bitpeers.py --file=sample_peers.dat --output=json
```

Feel free to suggest changes or leave comments in issues.
