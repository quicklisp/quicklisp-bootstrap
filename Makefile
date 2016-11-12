all:

tag:
	test -z "$(git status -s quicklisp.lisp)"
	git tag version-$(grep -Eohm1 2[0-9-]{9} quicklisp.lisp)
