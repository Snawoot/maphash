// Copyright 2022 Dolthub, Inc.
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

package maphash

import "unsafe"

type Seed struct {
	s uintptr
}

// Hasher hashes values of type K.
// Uses runtime AES-based hashing.
type Hasher[K comparable] struct {
	hash hashfn
	seed uintptr
}

// NewHasher creates a new Hasher[K] with a random seed.
func NewHasher[K comparable](seed Seed) Hasher[K] {
	return Hasher[K]{
		hash: getRuntimeHasher[K](),
		seed: seed.s,
	}
}

// NewSeed returns new seed from uintptr value
func NewSeed(s uintptr) Seed {
	return Seed{s}
}

// RandomSeed returns new random seed
func RandomSeed() Seed {
	return Seed{newHashSeed()}
}

// Hash hashes |key|.
func (h Hasher[K]) Hash(key K) uint64 {
	return uint64(h.Hash2(key))
}

// Hash2 hashes |key| as more flexible uintptr.
func (h Hasher[K]) Hash2(key K) uintptr {
	// promise to the compiler that pointer
	// |p| does not escape the stack.
	p := noescape(unsafe.Pointer(&key))
	return h.hash(p, h.seed)
}

// WithSeed returns copy of hasher with another seed
func (h Hasher[K]) WithSeed(seed Seed) Hasher[K] {
	return Hasher[K]{
		hash: h.hash,
		seed: seed.s,
	}
}
