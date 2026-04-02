#!/bin/bash
# Compile arc_paper.tex to PDF
# Run from the paper/ directory: bash compile.sh
# Requires: pdflatex (TeX Live or MiKTeX)

set -e
cd "$(dirname "$0")"

echo "Compiling arc_paper.tex..."
pdflatex -interaction=nonstopmode arc_paper.tex
pdflatex -interaction=nonstopmode arc_paper.tex
pdflatex -interaction=nonstopmode arc_paper.tex

echo "Done. Output: arc_paper.pdf"
