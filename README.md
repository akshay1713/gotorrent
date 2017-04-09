# gotorrent
A simple command line bittorrent client.

This enables file sharing via the bittorrent p2p protocol.

Currently, it can only download one torrent at a time, and only supports downloading, not uploading.
Both udp and http trackers are supported.

The application does not refresh peers at regular intervals, so it can download only very small files. 
However, it should be simple to implement and I plan to do that soon.

After that I will be shelving this project for the forseeable future.

Things I would like to add in the future -
* Multiple torrents at the same time.
* Seeding support.
* Web interface.
* Make it suitable for practical usage. A LOT needs to be done on this front.
  * Refresh peers by making regular tracker requests.
  * Handle choke/unchoke, dropped connections.
  * Handle existing file status while starting a torrent session.
  * Use better algorithms for requesting pieces, specially at the end. Will probably go with rarest first if I ever decide to go forward with this.

If I ever pick this project up again, these are the things I will be adding.
