#!/bin/sh

cd $(dirname $0)
LD_LIBRARY_PATH=. exec timeout -sKILL 30 ./chall
