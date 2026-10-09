// TODO: UniqueUserId.
package broker

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"icicle/internal/wire"
)

type outbound struct {
	data     []byte
	terminal bool
}

type peer struct {
	conn        *websocket.Conn
	out         chan outbound
	done        chan struct{}
	writerDone  chan struct{}
	once        sync.Once
	challenge   []byte
	key         []byte
	session     *session
	id          string
	request     *wire.JoinRequest
	admitted    bool
	deadline    time.Time
	tokens      float64
	lastMessage time.Time
	buffered    atomic.Int64
}

func (p *peer) close() {
	p.once.Do(func() {
		close(p.done)
		p.conn.Close()
	})
}

func (p *peer) send(message *wire.Envelope, terminal bool) bool {
	select {
	case <-p.done:
		return false
	default:
	}
	data, err := proto.Marshal(message)
	if err != nil {
		p.close()
		return false
	}
	if p.buffered.Add(int64(len(data))) > 256*1024 {
		p.buffered.Add(-int64(len(data)))
		p.close()
		return false
	}
	select {
	case p.out <- outbound{data, terminal}:
		return true
	default:
		p.buffered.Add(-int64(len(data)))
		p.close()
		return false
	}
}

func (p *peer) writeLoop() {
	defer close(p.writerDone)
	defer p.close()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case item := <-p.out:
			p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := p.conn.WriteMessage(websocket.BinaryMessage, item.data)
			p.buffered.Add(-int64(len(item.data)))
			if err != nil {
				return
			}
			if item.terminal {
				p.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "connection ended"), time.Now().Add(time.Second))
				return
			}
		case <-ticker.C:
			if err := p.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				return
			}
		}
	}
}
