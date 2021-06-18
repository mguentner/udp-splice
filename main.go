package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
)

const (
	MAX_UDP_PACKET_SIZE = 65536
	ADDR_RESOLVE_INTERVAL = time.Second * 60
)

type UDPPacket struct {
	*net.UDPAddr
	Data []byte
}

func parseAddress(address string, name string) (err error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return errors.New(fmt.Sprintf("%s address: %s", name, err))
	}
	return nil
}

func parseFlags() (listenAddress string, destinationAddresses []string, err error) {
	var listenAddressRaw string
	var destinationAddressesRaw []string
	flag.StringVar(&listenAddressRaw, "listen", "", "address that shall be multiplied")
	flag.StringSliceVar(&destinationAddressesRaw, "destination", []string{}, "destination addresses, may be supplied multiple times or seperated by comma")
	flag.Parse()

	if listenAddressRaw == "" {
		return "", []string{}, errors.New("Please set a listen address")
	}
	if err := parseAddress(listenAddressRaw, "listen"); err != nil {
		return "", []string{}, err
	}
	if len(destinationAddressesRaw) == 0 {
		return listenAddressRaw, []string{}, errors.New("Please provide at least one destination address")
	}
	for _, dest := range destinationAddressesRaw {
		if err := parseAddress(dest, "destination"); err != nil {
			return listenAddressRaw, []string{}, err
		}
	}
	return listenAddressRaw, destinationAddressesRaw, nil
}

func toggleSpliceEnabled(spliceEnabled *bool, destinations []string) {
	if (*spliceEnabled) {
		log.Printf("Disabling operation on secondary destinations: %v", destinations[1:])
	} else {
		log.Printf("Resuming operation on all destinations")
	}
	*spliceEnabled = !(*spliceEnabled)
}

func readPump(conn *net.UDPConn, readChan chan UDPPacket, done chan bool) {
	for {
		readBuffer := make([]byte, MAX_UDP_PACKET_SIZE)
		readBytes, addr, err := conn.ReadFromUDP(readBuffer)
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				// unexpected
				log.Printf("Read error: %s", err)
			}
			break
		}
		readChan <- UDPPacket{addr, readBuffer[:readBytes]}
	}
	done <- true
}

func sendPacketToDestinations(conn *net.UDPConn, destinations []*net.UDPAddr, data []byte) error {
	resChan := make(chan bool)
	for _, destination := range destinations {
		go func(dest *net.UDPAddr) {
			_, err := conn.WriteTo(data, dest)
			if err != nil {
				log.Printf("write error: %s", err)
			}
			resChan <- true
		}(destination)
	}
	resCount := 0
	for {
		if resCount == len(destinations) {
			return nil
		}
		resCount++
		<- resChan
	}
}

type DestinationAddrState struct {
	DestinationStringAddresses *[]string
	DestinationAddresses []*net.UDPAddr
	Mutex sync.RWMutex
}

func destinationAddrResolver(terminateChan chan bool, state *DestinationAddrState) {
	resolve := func() {
		destinationAddrs := []*net.UDPAddr{}
		for count, destinationStringAddress := range *state.DestinationStringAddresses {
			addr, err := net.ResolveUDPAddr("udp", destinationStringAddress)
			if err != nil {
				log.Printf("destination resolve error: %s", err)
				// if we cannot resolve the first addr, we must not confuse
				// the sorting
				if (count == 0) {
					return
				}
				continue
			}
			destinationAddrs = append(destinationAddrs, addr)
		}
		state.Mutex.Lock()
		state.DestinationAddresses = destinationAddrs
		state.Mutex.Unlock()
	}
	resolve()
	for {
		select {
		case <- time.After(ADDR_RESOLVE_INTERVAL):
			resolve()
		case <- terminateChan:
			return
		}
	}
}


/*

  Terminology:

   Peer 1 ---------- [ ingressConn ] --- [ mainLoop ] --- [ primaryEgressConn ] --- first destination (Peer 2)
                                               |----------[ secondaryEgressConn ] ---- Peer 3
                                                                                  |--- Peer 4
                                                                                  ...
                                                                                  |___ Peer n

   The connection between Peer 1 and Peer 2 is bi directional, if Peer 2 sends data back to primaryEgressConn, it will be
   also forwarded to Peer 1 via ingressConn.

   The addresses of Peer 2...n are solved periodically to keep them up to date as they might be DNS entries.
 */

func main() {
	// state start
	lastPacketSourceAddr := (*net.UDPAddr)(nil)
	spliceEnabled := true
	resolverState := DestinationAddrState{
		DestinationAddresses: []*net.UDPAddr{},
		DestinationStringAddresses: &[]string{},
		Mutex: sync.RWMutex{},
	}
	// state end
	listenAddressString, destinationStringAddresses, err := parseFlags()
	if err != nil {
		log.Fatalln(err)
	}
	listenAddress, err := net.ResolveUDPAddr("udp", listenAddressString)
	if err != nil {
		log.Fatalf("listener: %s", err)
	}
	ingressConn, err := net.ListenUDP("udp" , listenAddress)
	if err != nil {
		log.Fatalf("listener: %s", err)
	}
	defer ingressConn.Close()
	primaryEgressConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Fatalf("primary egress connection: %s", err)
	}
	defer primaryEgressConn.Close()
	secondaryEgressConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Fatalf("secondary egress connection: %s", err)
	}
	defer secondaryEgressConn.Close()

	ingressReceiveChan := make(chan UDPPacket, 16)
	primaryEgressReceiveChan := make(chan UDPPacket, 16)
	ingressReadPumpDone := make(chan bool)
	primaryEgressReadPumpDone := make(chan bool)
	terminateDestinationAddrResolverChan := make(chan bool)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)

	go readPump(ingressConn, ingressReceiveChan, ingressReadPumpDone)
	go readPump(primaryEgressConn, primaryEgressReceiveChan, primaryEgressReadPumpDone)

	resolverState.DestinationStringAddresses = &destinationStringAddresses
	go destinationAddrResolver(terminateDestinationAddrResolverChan, &resolverState)
	defer func () { terminateDestinationAddrResolverChan <- true }()

mainLoop:
	for {
		select {
		case packet := <- ingressReceiveChan:
			func (){
				resolverState.Mutex.RLock()
				lastPacketSourceAddr = packet.UDPAddr
				defer resolverState.Mutex.RUnlock()

				if len(*resolverState.DestinationStringAddresses) == 0 {
					return
				}

				err = sendPacketToDestinations(primaryEgressConn, resolverState.DestinationAddresses[:1], packet.Data)
				if err != nil {
					log.Printf("primary egress send error: %s", err)
					return
				}
				if (!spliceEnabled) {
					return
				}
				err = sendPacketToDestinations(secondaryEgressConn, resolverState.DestinationAddresses[1:], packet.Data)
				if err != nil {
					log.Printf("secondary egress send error: %s", err)
					return
				}
			}()
		case packet := <- primaryEgressReceiveChan:
			// we received a packet on the primary egress conn / socket, we send it back
			// to the last known address that sent to the ingress conn / socket
			if (lastPacketSourceAddr != nil) {
				ingressConn.WriteTo(packet.Data, lastPacketSourceAddr)
			}
		case signal := <- signalChan:
			switch signal {
			case syscall.SIGTERM:
				fallthrough
			case syscall.SIGINT:
				break mainLoop
			case syscall.SIGUSR1:
				toggleSpliceEnabled(&spliceEnabled, destinationStringAddresses)
			}
		case <- ingressReadPumpDone:
			log.Printf("UDP listener terminated")
			break mainLoop
		case <- primaryEgressReadPumpDone:
			log.Printf("UDP listener terminated")
			break mainLoop
		}
	}
}
