import base64
from itertools import cycle
from urllib.parse import unquote
from argparse import ArgumentParser, FileType


def xor(input, key):
	temp = bytes(a ^ b for a, b in zip(input, cycle(key.encode('utf-8'))))
	return temp


def checkArgumentValidity(parser, args):
	if not args.b64:
		parser.print_usage()
		print("No base64 string specified")
		return False

	else:
		return True


def main(b64, key):
	unxored = xor(base64.b64decode(unquote(b64)), key)
	print("UserAgent:", unxored.decode("utf-8"))


if __name__ == "__main__":
	parser = ArgumentParser(prog="smuggler-ua.py", description="Helper script that reverses the base64 value received on the /data?auth_key= request")
	parser.add_argument("b64", help="Base64 string as received (non url-decoded)")
	parser.add_argument("-k", "--key", action="store", dest="key", help="XOR key used for smuggling", default="P@ssw0rD")
	args = parser.parse_args()

	if not checkArgumentValidity(parser, args):
		exit(1)

	main(args.b64, args.key)