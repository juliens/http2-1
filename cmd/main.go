package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/dgrr/http2"
	"github.com/valyala/fasthttp"
)

func main() {
	go http.ListenAndServe(":8086", nil)
	ln, err := net.Listen("tcp", ":8085")
	if err != nil {
		log.Fatal(err)
	}

	for {
		fmt.Println("WAIT CONN")
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
		}
		go serverConn(conn)
	}
}

var b bool

func serverConn(conn net.Conn) {
	s := &fasthttp.Server{
		Handler: fasthttp.RequestHandler(func(ctx *fasthttp.RequestCtx) {

		}),
	}

	server := http2.ConfigureServer(s, http2.ServerConfig{})

	ids := map[uint32]uint32{}
	pids := map[uint32]func(fr *http2.FrameHeader){}
	var c *http2.Conn
	if b {
		connh2, err := net.Dial("tcp", "172.17.0.2:80")
		if err != nil {
			log.Fatal(err)
		}
		c = http2.NewConn(connh2, http2.ConnOpts{PingInterval: time.Second * 30})

	} else {
		connh2, err := net.Dial("tcp", "172.17.0.3:80")
		if err != nil {
			log.Fatal(err)
		}
		c = http2.NewConn(connh2, http2.ConnOpts{PingInterval: time.Second * 30})

	}
	b = !b

	c.ReadFn = func(fr *http2.FrameHeader) {
		pid := pids[fr.Stream()]
		if pid != nil {
			pid(fr)
		}

	}
	c.Handshake()

	server.HandleFrameFn = func(fw http2.FrameWriter, strm *http2.Stream, fr *http2.FrameHeader) error {
		pid := fr.Stream()
		id := ids[pid]

		id, _, _ = c.WriteFrameHeader(id, fr)
		pids[id] = func(fr *http2.FrameHeader) {
			frb := &http2.FrameHeader{}
			frb.Reset()
			frb.SetFlags(fr.Flags())
			frb.SetStream(pid)

			bodyNew := http2.AcquireFrame(fr.Type())
			bodyNew.Deserialize(fr)

			frb.SetBody(bodyNew)
			fw.WriteFrH(frb)

			http2.ReleaseFrame(bodyNew)
		}
		ids[pid] = id
		return nil
	}
	server.ServeConn(conn)
}
