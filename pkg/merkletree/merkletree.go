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

// Package merkletree implements Merkle tree generating and verification.
package merkletree

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// sha256DigestSize specifies the digest size of a SHA256 hash.
	sha256DigestSize = 32
)

// Size defines the scale of a Merkle tree.
type Size struct {
	// blockSize is the size of a data block to be hashed.
	blockSize int64
	// digestSize is the size of a generated hash.
	digestSize int64
	// hashesPerBlock is the number of hashes in a block. For example, if
	// blockSize is 4096 bytes, and digestSize is 32 bytes, there will be 128
	// hashesPerBlock. Therefore 128 hashes in a lower level will be put into a
	// block and generate a single hash in an upper level.
	hashesPerBlock int64
	// levelStart is the start block index of each level. The number of levels in
	// the tree is the length of the slice. The leafs (level 0) are hashes of
	// blocks in the input data. The levels above are hashes of lower level
	// hashes.  The highest level is the root hash.
	levelStart []int64
}

// MakeSize initializes and returns a new Size object describing the structure
// of a tree. dataSize specifies the number of the file system size in bytes.
func MakeSize(dataSize int64) Size {
	size := Size{
		blockSize: usermem.PageSize,
		// TODO(b/156980949): Allow config other hash methods (SHA384/SHA512).
		digestSize:     sha256DigestSize,
		hashesPerBlock: usermem.PageSize / sha256DigestSize,
	}
	numBlocks := (dataSize + size.blockSize - 1) / size.blockSize
	level := int64(0)
	offset := int64(0)

	// Calcuate the number of levels in the Merkle tree and the beginning offset
	// of each level. Level 0 is the level directly above the data blocks, while
	// level NumLevels - 1 is the root.
	for numBlocks > 1 {
		size.levelStart = append(size.levelStart, offset)
		// Round numBlocks up to fill up a block.
		numBlocks += (size.hashesPerBlock - numBlocks%size.hashesPerBlock) % size.hashesPerBlock
		offset += numBlocks / size.hashesPerBlock
		numBlocks = numBlocks / size.hashesPerBlock
		level++
	}
	size.levelStart = append(size.levelStart, offset)
	return size
}

// Generate constructs a Merkle tree for the contents of data. The output is
// written to treeWriter. The treeReader should be able to read the tree after
// it has been written. That is, treeWriter and treeReader should point to the
// same underlying data but have separate cursors.
func Generate(data io.Reader, dataSize int64, treeReader io.Reader, treeWriter io.Writer) ([]byte, error) {
	size := MakeSize(dataSize)

	numBlocks := (dataSize + size.blockSize - 1) / size.blockSize

	var root []byte
	for level := 0; level < len(size.levelStart); level++ {
		for i := int64(0); i < numBlocks; i++ {
			buf := make([]byte, size.blockSize)
			var (
				n   int
				err error
			)
			if level == 0 {
				// Read data block from the target file since level 0 is directly above
				// the raw data block.
				n, err = data.Read(buf)
			} else {
				// Read data block from the tree file since levels higher than 0 are
				// hashing the lower level hashes.
				n, err = treeReader.Read(buf)
			}

			// err is populated as long as the bytes read is smaller than the buffer
			// size. This could be the case if we are reading the last block, and
			// break in that case. If this is the last block, the end of the block
			// will be zero-padded.
			// This should only happen for level 0. For higher levels all the blocks
			// should have been zero-padded.
			if n == 0 && err == io.EOF && level == 0 {
				break
			} else if err != nil && err != io.EOF {
				return nil, err
			}
			// Hash the bytes in buf.
			digest := sha256.Sum256(buf)

			if level == len(size.levelStart)-1 {
				root = digest[:]
			}

			// Write the generated hash to the end of the tree file.
			if _, err = treeWriter.Write(digest[:]); err != nil {
				return nil, err
			}
		}
		// If the genereated digests do not round up to a block, zero-padding the
		// remaining of the last block. But no need to do so for root.
		if level != len(size.levelStart)-1 && numBlocks%size.hashesPerBlock != 0 {
			zeroBuf := make([]byte, size.blockSize-(numBlocks%size.hashesPerBlock)*size.digestSize)
			if _, err := treeWriter.Write(zeroBuf[:]); err != nil {
				return nil, err
			}
		}
		numBlocks = (numBlocks + size.hashesPerBlock - 1) / size.hashesPerBlock
	}
	return root, nil
}

// Verify verifies the content read from data with offset. The content is
// verified against tree. If content spans across multiple blocks, each block is
// verified. Verification fails if the hash in any level mismatches the hashes
// stored in the tree. In the end the calculated root hash is compared to
// expectedRoot, and fails it a mismatch happens.
func Verify(data io.ReadSeeker, tree io.ReadSeeker, dataSize int64, content []byte, offset int64, expectedRoot []byte) error {
	size := MakeSize(int64(dataSize))

	// Calculate the index of blocks that includes the content.
	blockStart := offset / size.blockSize
	blockEnd := (offset + int64(len(content)) - 1) / size.blockSize

	// Set data back to its original offset when verification finishes.
	origOffset, err := data.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("Seek origoffset failed: %v", err)
	}
	defer data.Seek(origOffset, io.SeekStart)

	// Move the the first block that contains content in data.
	if _, err = data.Seek(blockStart*size.blockSize, io.SeekStart); err != nil {
		return fmt.Errorf("Seek to datablock start failed: %v", err)
	}

	// dataStart is start index in content that belongs to the current
	// block.
	dataStart := int64(0)
	for i := blockStart; i <= blockEnd; i++ {
		// Read a block that includes all or part of content from data,
		// and replace the part that overlaps with content with content.
		buf := make([]byte, size.blockSize)
		n, err := data.Read(buf)
		// If content includes the the last block, it may not fill up a
		// whole block. The rest of buf is zero-padded.
		if err != nil && !(err == io.EOF && n != 0) {
			return fmt.Errorf("Read from data failed: %v", err)
		}
		// startIdx is the beginning index in the current block that's
		// part of content. For the first block, it is the position in
		// the block that content starts. For all other blocks it should
		// be 0.
		startIdx := int64(0)
		if i == blockStart {
			startIdx = offset % size.blockSize
		}
		// endIdx is the end index in the current block that's part of
		// content. For the last block, it is the position in the block
		// that content ends. For all other blocks it's block size.
		endIdx := size.blockSize
		if i == blockEnd {
			endIdx = (offset+int64(len(content))-1)%size.blockSize + 1
		}
		// dataEnd is end index in content that belongs to the current
		// block.
		dataEnd := dataStart + (endIdx - startIdx)

		copy(buf[startIdx:endIdx], content[dataStart:dataEnd])
		dataStart = dataEnd

		if err = verifyBlock(tree, size, buf, i, expectedRoot); err != nil {
			return err
		}
	}
	return nil
}

// verifyBlock verifies a block against tree. index is the number of block in
// original data. The block is verified through each level of the tree. It fails
// if the calculated hash from block is different from any level of hashes
// stored in tree. And the final root hash is compared with expectedRoot.
func verifyBlock(tree io.ReadSeeker, size Size, block []byte, index int64, expectedRoot []byte) error {
	if len(block) != int(size.blockSize) {
		return fmt.Errorf("incorrect block size")
	}

	digest := sha256.Sum256(block)
	expectedDigest := make([]byte, size.digestSize)
	for level := 0; level < len(size.levelStart); level++ {
		// Move to stored hash for the current block, read the digest
		// and store in expectedDigest.
		if _, err := tree.Seek(size.levelStart[level]*size.blockSize+index*size.digestSize, io.SeekStart); err != nil {
			return err
		}
		if _, err := tree.Read(expectedDigest); err != nil {
			return err
		}

		if !bytes.Equal(digest[:], expectedDigest) {
			return fmt.Errorf("Verification failed")
		}

		// If this is the root layer, no need to generate next level
		// hash.
		if level == len(size.levelStart)-1 {
			break
		}

		// Read a block in current level that contains the hash we just
		// generated, and generate a next level hash from it.
		index = index / size.hashesPerBlock
		if _, err := tree.Seek((size.levelStart[level]+index)*size.blockSize, io.SeekStart); err != nil {
			return err
		}
		if _, err := tree.Read(block); err != nil {
			return err
		}
		digest = sha256.Sum256(block)
	}

	// Verification for the tree succeeded. Now compare the root hash in the
	// tree with expectedRoot.
	if !bytes.Equal(digest[:], expectedRoot) {
		return fmt.Errorf("Verification failed")
	}
	return nil
}
