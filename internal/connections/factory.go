/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package connections

import (
	"fmt"
	"github.com/seek-ret/ebpf-training/workshop1/internal/structs"
	"sync"
	"time"
)

// Factory is a routine-safe container that holds a trackers with unique ID, and able to create new tracker.
type Factory struct {
	httpEvents uint32
	kafkaEvents uint32
	beginningTimestamp float64
	connections         map[structs.ConnID]*Tracker
	inactivityThreshold time.Duration
	mutex               *sync.RWMutex
}

// NewFactory creates a new instance of the factory.
func NewFactory(inactivityThreshold time.Duration) *Factory {
	return &Factory{
		connections:         make(map[structs.ConnID]*Tracker),
		beginningTimestamp:  float64(time.Now().UnixNano()),
		mutex:               &sync.RWMutex{},
		inactivityThreshold: inactivityThreshold,
	}
}

func (factory *Factory) HandleReadyConnections() {
	trackersToDelete := make(map[structs.ConnID]struct{})

	for connID, tracker := range factory.connections {
		// fmt.Printf("Handle ready connections function\n")
		// if tracker.IsComplete() {
			trackersToDelete[connID] = struct{}{}
			if len(tracker.sentBuf) == 0 && len(tracker.recvBuf) == 0 {
				continue
			}
			// fmt.Printf("Protocol: %d\n", tracker.protocol)
			fmt.Printf("\n\n========================>\nFound payload\n")
			if tracker.protocol == 1 {
				factory.httpEvents += 1
				fmt.Printf("Http packet captured\n")
			} else if tracker.protocol == 2 {
				factory.kafkaEvents += 1
				fmt.Printf("kafka packet captured\n")
				fmt.Printf("Kafka headers:\nAPI ID: %d\nAPI Version: %d\nCorrelation ID: %d\n", tracker.kafkaHeaders.ApiId, tracker.kafkaHeaders.ApiVersion, tracker.kafkaHeaders.CorrelationId)
			}
			numHttpEvents := float64(factory.httpEvents)
			numKafkaEvents := float64(factory.kafkaEvents)
			timeDiff := float64(time.Now().UnixNano()) - factory.beginningTimestamp
			fmt.Printf("Socket family: %d\nSocket address: %d\nSocket port: %d\n", tracker.addr.SinFamily, tracker.addr.SinAddr, tracker.addr.SinPort)
			fmt.Printf("Process ID: %d\nProcess name: %s\nRequest->\n%s\n\nResponse->\n%s\n\n<========================\n", tracker.connID.TGID, tracker.comm, tracker.recvBuf, tracker.sentBuf)
			fmt.Printf("No of HTTP protocol packets captured: %d\t Http Packets per minute: %f\n", factory.httpEvents, (numHttpEvents*60000000000)/timeDiff);
			fmt.Printf("No of Kafka protocol packets captured: %d\t Packets per minute: %f\n", factory.kafkaEvents, (numKafkaEvents*60000000000)/timeDiff);
			tracker.sentBuf = nil
			tracker.recvBuf = nil
		// } else if tracker.Malformed() {
		// 	trackersToDelete[connID] = struct{}{}
		// 	fmt.Printf("Malformed")
		// } else if tracker.IsInactive(factory.inactivityThreshold) {
		// 	trackersToDelete[connID] = struct{}{}
		// 	fmt.Printf("Inactive")
		// }
	}
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	// for key := range trackersToDelete {
	// 	delete(factory.connections, key)
	// }
}

// GetOrCreate returns a tracker that related to the given connection and transaction ids. If there is no such tracker
// we create a new one.
func (factory *Factory) GetOrCreate(connectionID structs.ConnID) *Tracker {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	tracker, ok := factory.connections[connectionID]
	if !ok {
		// fmt.Printf("New tracker created\n")
		// fmt.Printf("%d %d\n", connectionID.TGID, connectionID.FD)
		factory.connections[connectionID] = NewTracker(connectionID)
		return factory.connections[connectionID]
	}
	return tracker
}
