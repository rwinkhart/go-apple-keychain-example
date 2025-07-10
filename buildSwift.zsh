#!/bin/zsh
cd swift
swift build -c release
mv ./.build/release/libSwiftLibrary.dylib ../
cd ..
