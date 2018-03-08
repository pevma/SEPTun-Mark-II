all:
	rst2latex --documentclass=report --use-latex-toc --stylesheet=sept --documentoptions=a4wide SEPTun-Mark-II.rst>SEPTun-Mark-II.tex
	pdflatex SEPTun-Mark-II.tex
	pdflatex SEPTun-Mark-II.tex
