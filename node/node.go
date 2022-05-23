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
	port uint16
}

type Entry struct {
}

/*
 * Messages
 */
type NodeMsg struct {
	MsgType    uint8
	Term       int
	Entries    []string
	SenderPort uint16 // porque no se sabe la ip:puerto del origen (se sabe la ip solo), el puerto puede ser otro proceso que no es el que hace net.Dial y conn.Write
}

type UIMsg struct {
	MsgType uint8
	Term    int
	Enties  []string
	SrcPort uint16
	SrcIp   string
	DstPort uint16
	DstIp   string
}

type Event struct {
	msg    NodeMsg
	sender string // ip (the port is in msg.SenderPort)
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
 */
type NodeStatus struct {
	port               uint16         // self port
	mutex              sync.Mutex     // mutex for concurrent access
	peers              []NodeAddr     // list of peers
	received_votes     int8           // number of received votes in a election
	voted_current_term bool           // true if has voted in current term
	term               int            // current node term
	log                []NodeLogEntry // list of entries
	raftStatus         uint8          // raft status: follower | candidate | leader
	nodeStatus         string         // node status: "dead" | "alive"
	electionTimeout    int64          // election timeout (for followers and candidates) milliseconds
	leaderHeartbeat    int64          // heartbeat time interval (for leaders) milliseconds
	eventChan          chan Event     // channel to sync raft() and listener()
}

var promptPort string
var selfPort uint16

func main() {

	// Create tcp server
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		print("main", "Error listening")
		os.Exit(1)
	}
	tcpListener, ok := l.(*net.TCPListener)
	if !ok {
		print("main", "Error casting to net.TCPListener")
		os.Exit(1)
	}
	defer tcpListener.Close()

	selfPort = uint16(tcpListener.Addr().(*net.TCPAddr).Port)
	promptPort = strconv.Itoa(int(selfPort))
	print("main", fmt.Sprintf("Listening on port %d", selfPort))

	var wg sync.WaitGroup

	// initialize node status
	status := NodeStatus{
		port:               selfPort,
		peers:              []NodeAddr{},
		received_votes:     -1,
		voted_current_term: false,
		term:               0,
		log:                []NodeLogEntry{},
		raftStatus:         follower,
		nodeStatus:         "alive",
		electionTimeout:    5000, // milliseconds
		leaderHeartbeat:    3000, // milliseconds
		eventChan:          make(chan Event, 25),
	}

	// startup cli
	if len(os.Args) > 1 && os.Args[1] == "--nocli" {
		return
	}
	print("main", "Aviable commands are:")
	print("main", "\tADD: add peer")
	print("main", "\tPEERS: lists peers")
	print("main", "\tSTART: start node.")
	reader := bufio.NewReader(os.Stdin)
	//prompt := promptPort + "> "
	end := false
	started := false
	regexADD := regexp.MustCompile(`\s*ADD\s*(?P<args>[\w\W]*)`)
	regexSTOP := regexp.MustCompile(`\s*STOP\s*(?P<args>[\w\W]*)`)
	regexPEERS := regexp.MustCompile(`\s*PEERS\s*(?P<args>[\w\W]*)`)
	regexSTART := regexp.MustCompile(`\s*START\s*(?P<args>[\w\W]*)`)

	for !end {
		//fmt.Print(prompt)
		line, _, err := reader.ReadLine()
		//lineInput, err := reader.ReadString('\n')
		//line := []byte(lineInput)

		if err != nil {
			print("main", "Error reading line from stdin.")
			os.Exit(1)
		}
		// ADD command
		if match := regexADD.FindSubmatch(line); len(match) > 0 {
			splittedArgs := strings.Split(string(match[1]), ":")
			switch {
			case len(splittedArgs) != 2:
				print("main", "Error: could not read argument string, must have \"ip:port\" format.")
			default:
				ip := splittedArgs[0]
				port := splittedArgs[1]
				nPort, err := strconv.Atoi(port)

				//print("main", fmt.Sprintf("ip: \"%s\"", ip))
				//print("main", fmt.Sprintf("port: \"%d\"", nPort))

				if err != nil || len(port) == 0 {
					print("main", fmt.Sprintf("Error: port value \"%s\"is not an integer.\n", port))
					continue
				}
				status.mutex.Lock()
				status.peers = append(status.peers, NodeAddr{ip, uint16(nPort)})
				status.mutex.Unlock()
				print("main", fmt.Sprintf("Added peer %s:%d", ip, nPort))
			}
			continue
		}
		// STOP command
		if match := regexSTOP.FindSubmatch(line); len(match) > 0 {
			print("main", "Stopping... ")
			status.mutex.Lock()
			status.nodeStatus = "dead"
			status.mutex.Unlock()
			end = true
			break
		}
		// PEERS command
		if match := regexPEERS.FindSubmatch(line); len(match) > 0 {
			print("main", "Peers:")
			for _, v := range status.peers {
				print("main", fmt.Sprintf("\t%s:%d", v.ip, v.port))
			}
			continue
		}
		// START command
		if match := regexSTART.FindSubmatch(line); len(match) > 0 {
			if started {
				print("main", "Error: node is already running")
				continue
			}
			print("main", "Starting node...")
			wg.Add(2)
			// Run response handler
			go listener(&wg, tcpListener, &status)
			// Run main algorithm
			go raft(&wg, &status)
			started = true
			print("main", "Started node")
			continue
		}

		fmt.Println("Unrecognized command. Aviable commands are:")
		fmt.Println("\tADD: add peer")
		fmt.Println("\tPEERS: lists peers")
		fmt.Println("\tSTOP: stop node")
		fmt.Println("\tSTART: start the server")

	}

	wg.Wait()
	print("main", "Stopped node.")
}

func addPeer(status *NodeStatus, ip string, port int) {
	status.mutex.Lock()
	status.peers = append(status.peers, NodeAddr{ip, uint16(port)})
	status.mutex.Unlock()
}

/*
 * Function that listens for new incoming messages
 */
func listener(wg *sync.WaitGroup, l *net.TCPListener, status *NodeStatus) {
	defer wg.Done()
	for {
		var timeout time.Time
		status.mutex.Lock()
		if status.nodeStatus == "dead" {
			close(status.eventChan) // terminate raft()
			status.mutex.Unlock()
			break
		}
		// set electionTimeout
		timeout = time.Now().Add(time.Millisecond * time.Duration(status.electionTimeout))

		// set timeout only for follower and candidate state
		sendTimeout := true
		if status.raftStatus == leader {
			sendTimeout = false
		}

		status.mutex.Unlock()

		l.SetDeadline(timeout)

		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if sendTimeout {
					print("listener", "Timeout accepting")
					// timeout for follower and candidate
					//go startElection(status)
					status.eventChan <- Event{
						// no hace falta rellenar los demas campos
						msg: NodeMsg{MsgType: followerTimeout},
					}
				} else {
					// timeout but its in leader state
				}
				continue
			} else {
				fmt.Println("Error accepting")
				os.Exit(1)
			}
		}

		go responseHandler(conn, status)
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

	fmt.Println("sender:", conn.RemoteAddr().String())

	status.eventChan <- Event{
		msg:    msg,
		sender: conn.RemoteAddr().(*net.TCPAddr).IP.String(),
	}
}

/*
 *Function that runs the main raft alforithm
 */
func raft(wg *sync.WaitGroup, status *NodeStatus) {
	defer wg.Done()
	fmt.Println("from raft(): ", status.peers)
	//electionTimer(status)

	for event := range status.eventChan {
		print("raft",
			fmt.Sprintf(
				"New event: %s(%d) from %s:%d",
				msgTypeToString(event.msg.MsgType),
				event.msg.MsgType,
				event.sender,
				event.msg.SenderPort),
		)
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
					go sendMsg(
						NodeMsg{
							MsgType: grantVote,
							Term:    event.msg.Term,
						},
						event.sender,
						event.msg.SenderPort,
					)
				}
			case candidate:
				if event.msg.Term > status.term {
					print("raft", fmt.Sprintf("Becoming follower of term %d", event.msg.Term))
					status.voted_current_term = true
					status.raftStatus = follower
					status.term = event.msg.Term
					go sendMsg(
						NodeMsg{
							MsgType: grantVote,
							Term:    event.msg.Term,
						},
						event.sender,
						event.msg.SenderPort,
					)
				}
			case leader:
				// si es lider entonces ver si el term es superior
				if event.msg.Term > status.term {
					print("raft", fmt.Sprintf("Becoming follower of term %d", event.msg.Term))
					status.voted_current_term = true
					status.raftStatus = follower
					status.term = event.msg.Term
					go sendMsg(
						NodeMsg{
							MsgType: grantVote,
							Term:    event.msg.Term,
						},
						event.sender,
						event.msg.SenderPort,
					)
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
						print(
							"raft",
							fmt.Sprintf("Becoming leader of term %d with %d votes",
								status.term,
								status.received_votes),
						)
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
				for _, e := range event.msg.Entries {
					status.log = append(status.log, NodeLogEntry{msg: e, timestamp: time.Now()})
				}
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
	print("raft", "Finished executing raft()")
}

func startElection(status *NodeStatus) {

	print("startElection", "Starting election")

	status.mutex.Lock()

	status.raftStatus = candidate
	status.term++
	status.received_votes = 1 // vote for itself

	msg := NodeMsg{
		MsgType:    requestVote,
		Term:       status.term,
		Entries:    nil,
		SenderPort: status.port,
	}
	status.mutex.Unlock()

	// send request vote to peers
	for _, p := range status.peers {
		go sendMsg(msg, p.ip, p.port)
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
			MsgType:    appendEntries,
			Term:       status.term,
			Entries:    nil,
			SenderPort: status.port,
		}
		timeout := status.leaderHeartbeat
		status.mutex.Unlock()

		// send AppendEntries to peers
		for _, p := range status.peers {
			go sendMsg(msg, p.ip, p.port)
		}

		// wait for next hearbeat
		<-time.After(time.Duration(timeout) * time.Millisecond)
	}

}

// selfPort is in msg
func sendMsg(msg NodeMsg, ip string, port uint16) {
	addr := ip + ":" + strconv.Itoa(int(port))
	print(
		"sendMsg",
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

	uiMsg := UIMsg{
		MsgType: msg.MsgType,
		Term:    msg.Term,
		Enties:  msg.Entries,
		SrcPort: selfPort,
		SrcIp:   "localhost",
		DstPort: port,
		DstIp:   ip,
	}

	// para cuando no hay sniffer
	conn2, err2 := net.Dial("udp", "0.0.0.0:3333")
	if err2 != nil {
		fmt.Printf("Error dialing %s\n", addr)
		return
	}
	enc2 := json.NewEncoder(conn2)
	if enc2.Encode(uiMsg) != nil {
		fmt.Println("Error encoding msg:", uiMsg)
	}
	conn2.Close()
}

func msgTypeToString(msgType uint8) string {
	switch msgType {
	case requestVote:
		return "requestVote"
	case appendEntries:
		return "appendEntries"
	case followerTimeout:
		return "followerTimeout"
	case grantVote:
		return "grantVote"
	default:
		return "unknownType"
	}
}

func print(method string, msg string) {
	fmt.Printf("[%s][%s]: %s\n", promptPort, method, msg)
}
