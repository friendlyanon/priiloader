all:
	@cp -r Installer/data nand
	@cp priiloader/hacks_hash.ini nand/data
	$(MAKE) -C loader
	$(MAKE) -C priiloader
	$(MAKE) -C Installer
	$(MAKE) -C nand

clean:
	@rm -rf nand/data
	$(MAKE) -C loader clean
	$(MAKE) -C priiloader clean
	$(MAKE) -C Installer clean
	$(MAKE) -C nand clean
