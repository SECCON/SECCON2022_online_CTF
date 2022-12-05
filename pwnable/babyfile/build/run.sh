#!/bin/sh

cd $(dirname $0)
exec timeout -sKILL 60 ./chall
