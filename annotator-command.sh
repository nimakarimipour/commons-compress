lib=true
arg=true
poly=true
rm -rvf target
ANNOTATOR_POLY=$poly ANNOTATOR_LIBRARY=$lib ANNOTATOR_TYPE_ARG=$arg mvn compile -Drat.skip=true