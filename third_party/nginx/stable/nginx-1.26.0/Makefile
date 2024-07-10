
default:	build

clean:
	rm -rf Makefile objs

.PHONY:	default clean

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/etc/nginx/sbin/ -t

	kill -USR2 `cat /etc/nginx//logs/nginx.pid`
	sleep 1
	test -f /etc/nginx//logs/nginx.pid.oldbin

	kill -QUIT `cat /etc/nginx//logs/nginx.pid.oldbin`

.PHONY:	build install modules upgrade
