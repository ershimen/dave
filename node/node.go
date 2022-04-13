package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
 * States of a node
 */
const (
	follower uint8 = iota
	candidate
	leader
)

// Types of messages
const (
	requestVote uint8 = iota
	appendEntries
	followerTimeout
	grantVote
)

/*
 * Peer
 */
type NodeAddr struct {
	ip   string
	port int16
}

type Entry struct {
}

/*
 * Messages
 */
type NodeMsg struct {
	MsgType uint8
	Term    int
	Entries []string
}

type Event struct {
	msg    NodeMsg
	sender string // ip:port
}

/*
 * Log entry
 */
type NodeLogEntry struct {
	msg       string
	timestamp time.Time
}

/*
 * Status of the raft algorithm.
 *	peers: List of peers
 *	received_votes: Number of votes receiver in a votation
 *	term: Numer of the current term
 *	log: List of log entries
 *	status: Status of the raft algorithm. This way goroutines can end
 */
type NodeStatus struct {
	mutex              sync.Mutex
	peers              []NodeAddr
	received_votes     int8
	voted_current_term bool
	term               int
	log                []NodeLogEntry
	raftStatus         uint8
	nodeStatus         string
	electionTimeout    int64 // milliseconds
	leaderHeartbeat    int64
	eventChan          chan Event
}

func main() {

	status := NodeStatus{
		peers:              []NodeAddr{},
		received_votes:     -1,
		voted_current_term: false,
		term:               0,
		log:                []NodeLogEntry{},
		raftStatus:         follower,
		nodeStatus:         "alive",
		electionTimeout:    150,
		leaderHeartbeat:    50,
		eventChan:          make(chan Event, 25),
	}

	// Create tcp server
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		fmt.Println("Error listening")
		os.Exit(1)
	}
	tcpListener, ok := l.(*net.TCPListener)
	if !ok {
		fmt.Println("Error casting to net.TCPListener")
		os.Exit(1)
	}

	defer tcpListener.Close()
	fmt.Println("Listening on port", tcpListener.Addr().(*net.TCPAddr).Port)

	// Run response handler
	go listener(tcpListener, &status)

	var wg sync.WaitGroup
	wg.Add(2)

	// Run main algorithm
	go raft(&wg, &status)

	// Create cli
	reader := bufio.NewReader(os.Stdin)
	prompt := strconv.Itoa(tcpListener.Addr().(*net.TCPAddr).Port) + "> "
	end := false
	regexADD := regexp.MustCompile(`\s*ADD\s*(?P<args>[\w\W]*)`)
	regexSTOP := regexp.MustCompile(`\s*STOP\s*(?P<args>[\w\W]*)`)
	regexPEERS := regexp.MustCompile(`\s*PEERS\s*(?P<args>[\w\W]*)`)

	fmt.Println("Node console")
	for !end {
		fmt.Print(prompt)
		line, _, err := reader.ReadLine()
		if err != nil {
			fmt.Fprint(os.Stderr, "Error reading line from stdin.")
			break
		}
		// ADD command
		if match := regexADD.FindSubmatch(line); len(match) > 0 {
			splittedArgs := strings.Split(string(match[1]), ":")
			switch {
			case len(splittedArgs) != 2:
				fmt.Println("Error: could not read argument string, must have \"ip:port\" format.")
			default:
				ip := splittedArgs[0]
				port := splittedArgs[1]
				nPort, err := strconv.Atoi(port)
				fmt.Println("ip: \"" + ip + "\"")
				fmt.Println("port: \"" + port + "\"")
				if err != nil || len(port) == 0 {
					fmt.Printf("Error: port value \"%s\"is not an integer.\n", port)
				}
				addPeer(&status, ip, nPort)
				fmt.Printf("Added peer %s:%d\n", ip, nPort)
			}
			continue
		}
		// STOP command
		if match := regexSTOP.FindSubmatch(line); len(match) > 0 {
			fmt.Print("Stopping... ")
			end = true
			continue
		}
		// PEERS command
		if match := regexPEERS.FindSubmatch(line); len(match) > 0 {
			fmt.Println("Peers:")
			for _, v := range status.peers {
				fmt.Println("\t" + v.ip + ":" + strconv.Itoa(int(v.port)))
			}
			fmt.Println()
			continue
		}
		fmt.Println("Unrecognized command. Aviable commands are:")
		fmt.Println("\tADD: add peer")
		fmt.Println("\tPEERS: lists peers")
		fmt.Println("\tSTOP: stop node.")
	}
	if end { // porque podria hacer break en readstring()
		wg.Wait()
		fmt.Println("Stopped node.")
	}
}

func addPeer(status *NodeStatus, ip string, port int) {
	status.mutex.Lock()
	status.peers = append(status.peers, NodeAddr{ip, int16(port)})
	status.mutex.Unlock()
}

/*
 * Function that listens for new incoming messages
 */
func listener(l *net.TCPListener, status *NodeStatus) {
	for {
		var timeout time.Time
		status.mutex.Lock()
		if status.nodeStatus == "dead" {
			break
		}
		switch status.raftStatus {
		case follower, candidate:
			// set electionTimeout
			timeout = time.Now().Add(time.Millisecond * time.Duration(status.electionTimeout))
		case leader:
			// no timeout
			timeout = time.Time{}
		}
		status.mutex.Unlock()

		l.SetDeadline(timeout)

		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				print("listener", "Timeout accepting")
				// timeout for follower and candidate
				//go startElection(status)
				status.eventChan <- Event{
					// no hace falta rellenar los demas campos
					msg: NodeMsg{MsgType: followerTimeout},
				}
				continue
			} else {
				fmt.Println("Error accepting")
				os.Exit(1)
			}
		}

		go responseHandler(conn, status)

		/*
			buffer := make([]byte, 2048)
			_, err = conn.Read(buffer)
			if err != nil {
				fmt.Println("Error reading from socket")
				os.Exit(1)
			}
			go responseHandler(conn, buffer, status)
		*/
	}

	print("listener", "Exiting listener goroutine...")
}

/*
 * Function that replies to messages
 */
func responseHandler(conn net.Conn, status *NodeStatus) {

	decoder := json.NewDecoder(conn)
	defer conn.Close()

	var msg NodeMsg
	err := decoder.Decode(&msg)
	if err != nil {
		fmt.Println("Error decoding message.")
		return
	}

	status.eventChan <- Event{
		msg:    msg,
		sender: conn.RemoteAddr().String(),
	}

	/*
		status.mutex.Lock()
		defer status.mutex.Unlock()

		switch msg.MsgType {
		// si es una peticion de votacion
		case requestVote:
			switch status.raftStatus {
			case follower:
				// responder con aceptar
				// poner voted_current_term a true
				status.voted_current_term = true
			case candidate:
				// si es candidato, entonces responder solo si el term del mensaje es mayor
				if msg.Term > status.term {
					status.raftStatus = follower
					status.term = msg.Term
				} else if msg.Term == status.term {
					//

				}

				// si es lider no hace falta responder
			}
		// si es una peticion de entries
		case append_entries:
			switch status.raftStatus {
			case follower:
				status.log = append(status.log, NodeLogEntry{msg: msg.entries[0], timestamp: time.Now()})
			case candidate:
				if msg.term > status.term { // si es candidato y le llega un mensaje con un term superior -> pasar a follower
					status.raftStatus = follower
					status.term = msg.term
				}
			case leader:
				// si le llega un mensaje con term superior entonces pasar a follower de ese term
				if msg.term > status.term {
					status.raftStatus = follower
					status.term = msg.term
				}
			}
		}
	*/
}

/*
 *Function that runs the main raft alforithm
 */
func raft(wg *sync.WaitGroup, status *NodeStatus) {
	defer wg.Done()
	fmt.Println("from raft(): ", status.peers)
	//electionTimer(status)

	for event := range status.eventChan {
		print("raft", fmt.Sprintf("New event: %s", msgTypeToString(event.msg.MsgType)))
		status.mutex.Lock()
		switch event.msg.MsgType {
		case requestVote:
			switch status.raftStatus {
			case follower:
				// si el term es superior y no se ha votado este term, aceptar el voto
				if event.msg.Term > status.term && !status.voted_current_term {
					print("raft", fmt.Sprintf("Becoming follower of term %d", event.msg.Term))
					status.voted_current_term = true
					status.term = event.msg.Term
					go sendMsg(NodeMsg{MsgType: grantVote, Term: event.msg.Term}, event.sender)
				}
			case candidate:
				if event.msg.Term > status.term {
					print("raft", fmt.Sprintf("Becoming follower of term %d", event.msg.Term))
					status.voted_current_term = true
					status.raftStatus = follower
					status.term = event.msg.Term
					go sendMsg(NodeMsg{MsgType: grantVote, Term: event.msg.Term}, event.sender)
				}
			case leader:
				// si es lider entonces ver si el term es superior
				if event.msg.Term > status.term {
					print("raft", fmt.Sprintf("Becoming follower of term %d", event.msg.Term))
					status.voted_current_term = true
					status.raftStatus = follower
					status.term = event.msg.Term
					go sendMsg(NodeMsg{MsgType: grantVote, Term: event.msg.Term}, event.sender)
				}
			}

		case grantVote:
			switch status.raftStatus {
			case follower:
				// no hace nada porque ya se termino la eleccion
			case candidate:
				// mirar si es un voto a nuestra eleccion
				if event.msg.Term == status.term {
					status.received_votes++
					if int(status.received_votes) > (len(status.peers)+1)/2 {
						print("raft", fmt.Sprintf("Becoming leader of term %d with %d votes", status.term, status.received_votes))
						status.raftStatus = leader
						go leaderHeartbeats(status)
					}
				}
			case leader:
				// no hacer nada porque ya se ha conseguido ser lider
			}

		case appendEntries:
			switch status.raftStatus {
			case follower:
				if event.msg.Term > status.term {
					print("raft", fmt.Sprintf("Becoming follower of term %d", event.msg.Term))
					status.voted_current_term = true
					status.raftStatus = follower
					status.term = event.msg.Term
				}
				// append entry
			case candidate:
				if event.msg.Term > status.term {
					print("raft", fmt.Sprintf("Becoming follower of term %d", event.msg.Term))
					status.voted_current_term = true
					status.raftStatus = follower
					status.term = event.msg.Term
				}
			case leader:
				if event.msg.Term > status.term {
					print("raft", fmt.Sprintf("Becoming follower of term %d", event.msg.Term))
					status.voted_current_term = true
					status.raftStatus = follower
					status.term = event.msg.Term
				}
			}

		case followerTimeout:
			switch status.raftStatus {
			case follower:
				go startElection(status)
				// start election
			case candidate:
				// start another election
				go startElection(status)
			case leader:
				// ignore
			}
		}

		status.mutex.Unlock()
	}
}

/*
func electionTimer(status *NodeStatus) {
	ticker := time.NewTicker(time.Millisecond * 150)
	defer ticker.Stop()
	for {
		select {
		case <-status.electionTimeoutChan:
			// incoming message
		case <-time.After(50 * time.Millisecond):
			// start election
			startElection(status)
		}

	}
}
*/

func startElection(status *NodeStatus) {

	print("startElection", "Starting election")

	status.mutex.Lock()

	status.raftStatus = candidate
	status.term++
	status.received_votes = 1 // vote for itself

	msg := NodeMsg{
		MsgType: requestVote,
		Term:    status.term,
		Entries: nil,
	}
	status.mutex.Unlock()

	// send request vote to peers
	for _, p := range status.peers {
		go sendMsg(msg, p.ip+":"+strconv.Itoa(int(p.port)))
	}
}

func leaderHeartbeats(status *NodeStatus) {
	for {
		status.mutex.Lock()
		if status.nodeStatus == "dead" || status.raftStatus != leader {
			status.mutex.Unlock()
			return
		}

		msg := NodeMsg{
			MsgType: appendEntries,
			Term:    status.term,
			Entries: nil,
		}
		timeout := status.leaderHeartbeat
		status.mutex.Unlock()

		// send AppendEntries to peers
		for _, p := range status.peers {
			go sendMsg(msg, p.ip+":"+strconv.Itoa(int(p.port)))
		}

		// wait for next hearbeat
		<-time.After(time.Duration(timeout) * time.Millisecond)
	}

}

func sendMsg(msg NodeMsg, addr string) {
	print("sendMsg",
		fmt.Sprintf("Sending %s to %s",
			msgTypeToString(msg.MsgType),
			addr),
	)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("Error dialing %s\n", addr)
		return
	}
	enc := json.NewEncoder(conn)
	if enc.Encode(msg) != nil {
		fmt.Println("Error encoding msg:", msg)
	}
	conn.Close()
}

func msgTypeToString(msgType uint8) string {
	switch msgType {
	case requestVote:
		return "requestVote"
	case appendEntries:
		return "appendEntries"
	case followerTimeout:
		return "followerTimeout"
	default:
		return "unknownType"
	}
}

func print(method string, msg string) {
	fmt.Printf("[%s]: %s\n", method, msg)
}
