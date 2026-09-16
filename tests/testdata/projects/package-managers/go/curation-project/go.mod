module github.com/you/hello

go 1.20

require rsc.io/quote v1.5.2

require (
	rsc.io/sampler v1.3.0 // indirect
)

require example.com/localmod v0.0.0

replace example.com/localmod => ./localmod
