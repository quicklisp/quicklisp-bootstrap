all:

tag:
	test -z "`git status -s quicklisp.lisp`"
	git tag version-`grep 'defvar qlqs-info:.version.' quicklisp.lisp | cut -d\" -f 2`
