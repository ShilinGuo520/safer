safer.out:safer.o
	gcc -o $@ $^
.c.o:
	gcc -c $<

clean:
	rm *.out *.o
