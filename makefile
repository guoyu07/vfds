SUBDIRS = lib src
installdir = /home/nemo
#curday = $(shell date '+%Y%m%d')
all:
	@list='$(SUBDIRS)'; for subdir in $$list; do \
		echo "Making all in $$list"; \
		(cd $$subdir && make); \
		done;

clean:
	@list='$(SUBDIRS)'; for subdir in $$list; do \
		echo "Making all in $$list"; \
		(cd $$subdir && make clean); \
		done;

install:
	rm -rf $(installdir)/*;
	mkdir $(installdir)/bin -p;
	mkdir $(installdir)/log -p;
	mkdir $(installdir)/conf -p;
	mkdir $(installdir)/data -p;
	mkdir $(installdir)/path/tmpdir -p;
	mkdir $(installdir)/path/outdir -p;
