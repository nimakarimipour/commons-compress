lib=true
arg=true
poly=true
cf_version="3.42.0"
ucrt_version="0.1-alpha-2"
rm -rvf target
CF_VERSION=$cf_version UCRT_VERSION=$ucrt_version ANNOTATOR_POLY=$poly ANNOTATOR_LIBRARY=$lib ANNOTATOR_TYPE_ARG=$arg mvn compile -Drat.skip=true