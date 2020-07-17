// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merkletree

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/usermem"
)

func TestSize(t *testing.T) {
	testCases := []struct {
		dataSize           int64
		expectedLevelStart []int64
	}{
		{
			dataSize:           100,
			expectedLevelStart: []int64{0},
		},
		{
			dataSize:           1000000,
			expectedLevelStart: []int64{0, 2, 3},
		},
		{
			dataSize:           4096 * int64(usermem.PageSize),
			expectedLevelStart: []int64{0, 32, 33},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.dataSize), func(t *testing.T) {
			s := MakeSize(tc.dataSize)
			if s.blockSize != int64(usermem.PageSize) {
				t.Errorf("got blockSize %d, want %d", s.blockSize, usermem.PageSize)
			}
			if s.digestSize != sha256DigestSize {
				t.Errorf("got digestSize %d, want %d", s.digestSize, sha256DigestSize)
			}
			if len(s.levelStart) != len(tc.expectedLevelStart) {
				t.Errorf("got levels %d, want %d", len(s.levelStart), len(tc.expectedLevelStart))
			}
			for i := 0; i < len(s.levelStart) && i < len(tc.expectedLevelStart); i++ {
				if s.levelStart[i] != tc.expectedLevelStart[i] {
					t.Errorf("got levelStart[%d] %d, want %d", i, s.levelStart[i], tc.expectedLevelStart[i])
				}
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	// The input data has size dataSize. It starts with the data in startWith,
	// and all other bytes are zeroes.
	testCases := []struct {
		dataSize     int
		startWith    []byte
		expectedRoot []byte
	}{
		{
			dataSize:     usermem.PageSize,
			startWith:    nil,
			expectedRoot: []byte{173, 127, 172, 178, 88, 111, 198, 233, 102, 192, 4, 215, 209, 209, 107, 2, 79, 88, 5, 255, 124, 180, 124, 122, 133, 218, 189, 139, 72, 137, 44, 167},
		},
		{
			dataSize:     128*usermem.PageSize + 1,
			startWith:    nil,
			expectedRoot: []byte{62, 93, 40, 92, 161, 241, 30, 223, 202, 99, 39, 2, 132, 113, 240, 139, 117, 99, 79, 243, 54, 18, 100, 184, 141, 121, 238, 46, 149, 202, 203, 132},
		},
		{
			dataSize:     1,
			startWith:    []byte{'a'},
			expectedRoot: []byte{52, 75, 204, 142, 172, 129, 37, 14, 145, 137, 103, 203, 11, 162, 209, 205, 30, 169, 213, 72, 20, 28, 243, 24, 242, 2, 92, 43, 169, 59, 110, 210},
		},
		{
			dataSize:     1,
			startWith:    []byte{'1'},
			expectedRoot: []byte{74, 35, 103, 179, 176, 149, 254, 112, 42, 65, 104, 66, 119, 56, 133, 124, 228, 15, 65, 161, 150, 0, 117, 174, 242, 34, 115, 115, 218, 37, 3, 105},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.dataSize), func(t *testing.T) {
			var (
				data bytes.Buffer
				tree bytes.Buffer
			)

			startSize := len(tc.startWith)
			_, err := data.Write(tc.startWith)
			if err != nil {
				t.Fatalf("Failed to write to data: %v", err)
			}
			_, err = data.Write(make([]byte, tc.dataSize-startSize))
			if err != nil {
				t.Fatalf("Failed to write to data: %v", err)
			}

			root, err := Generate(&data, int64(tc.dataSize), &tree, &tree)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			if !bytes.Equal(root, tc.expectedRoot) {
				t.Errorf("Unexpected root")
			}
		})
	}
}

// bytesReadWriter is used to read from/write to/seek in a byte array. Unlike
// bytes.Buffer, it keeps the whole buffer during read so that it can be reused.
type bytesReadWriteSeeker struct {
	// bytes contains the underlying byte array.
	bytes []byte
	// readPos is the currently location for Read. Write always appends to
	// the end of the array.
	readPos int
}

func (brws *bytesReadWriteSeeker) Write(p []byte) (int, error) {
	brws.bytes = append(brws.bytes, p...)
	return len(p), nil
}

func (brws *bytesReadWriteSeeker) Read(p []byte) (int, error) {
	if brws.readPos >= len(brws.bytes) {
		return 0, io.EOF
	}
	bytesRead := copy(p, brws.bytes[brws.readPos:])
	brws.readPos += bytesRead
	if bytesRead < len(p) {
		return bytesRead, io.EOF
	}
	return bytesRead, nil
}

func (brws *bytesReadWriteSeeker) Seek(offset int64, whence int) (int64, error) {
	off := offset
	if whence == io.SeekCurrent {
		off += int64(brws.readPos)
	}
	if whence == io.SeekEnd {
		off += int64(len(brws.bytes))
	}
	if off < 0 {
		panic("seek with negative offset")
	}
	if off >= int64(len(brws.bytes)) {
		return 0, io.EOF
	}
	brws.readPos = int(off)
	return off, nil
}

func TestVerify(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	// Use a random dataSize. 20000 * pagesize covers 4 level trees.
	// Minimum size 2 so that we can pick a random portion from it.
	dataSize := rand.Int63n(20000*usermem.PageSize) + 2
	data := make([]byte, dataSize)
	// Generate random bytes in data.
	rand.Read(data)
	var tree bytesReadWriteSeeker

	root, err := Generate(bytes.NewBuffer(data), int64(dataSize), &tree, &tree)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Pick a random portion of data.
	start := rand.Int63n(dataSize - 1)
	end := start + rand.Int63n(dataSize-start) + 1
	randPortion := data[start:end]

	// Checks that the random portion of data from the original data is
	// verified successfully.
	if err := Verify(bytes.NewReader(data), &tree, dataSize, randPortion, int64(start), root); err != nil {
		t.Errorf("Verification failed for correct data: %v", err)
	}

	// Flip a random bit in randPortion, and check that verification fails.
	randBytePos := rand.Int63n(end - start)
	randPortion[randBytePos] ^= 1

	if err := Verify(bytes.NewReader(data), &tree, dataSize, randPortion, int64(start), root); err == nil {
		t.Errorf("Verification succeeded for modified data")
	}
}
