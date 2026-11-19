package beefscan

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Honest BEEFs, built the way wallets and the TS SDK build them: V1 by
// Transaction.BEEF (the TS TopicBroadcaster sends tx.toBEEF(), which writes the
// same layout), V2 by Beef.MergeTransaction, Atomic by AtomicBEEF.

// tvznOrdLock is the real mainnet BSV-21 OrdLock listing script that
// internal/overlay/topics/ordlock_test.go vendors from the DEX repo.
const tvznOrdLock = "0063036f726451126170706c69636174696f6e2f6273762d3230004c767b2270223a226273762d3230222c226f70223a227472616e73666572222c22616d74223a223132303030222c226964223a22313765626432666337396262363737316431303264346333303138623562643263643930386663626232396137333239323732386433646662653562383862315f30227d682097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c0000145e4b9e78ae774eaeadcf05bd06a0ffbe4272fd1122000e2707000000001976a91428672b084a32711ee267c1e61f49771784620e9f88ac615179547a75537a537a537a0079537a75527a527a7575615579008763567901c161517957795779210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081059795679615679aa0079610079517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e81517a75615779567956795679567961537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00517951796151795179970079009f63007952799367007968517a75517a75517a7561527a75517a517951795296a0630079527994527a75517a6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f7754537993527993013051797e527e54797e58797e527e53797e52797e57797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a756100795779ac517a75517a75517a75517a75517a75517a75517a75517a75517a7561517a75517a756169587951797e58797eaa577961007982775179517958947f7551790128947f77517a75517a75618777777777777777777767557951876351795779a9876957795779ac777777777777777767006868"

// blockTreeHeight is the merkle tree height of a block of about a million
// transactions, as BSV blocks now carry.
const blockTreeHeight = 20

func p2pkhScript() *script.Script {
	s := script.Script(append(append([]byte{0x76, 0xa9, 0x14}, make([]byte, 20)...), 0x88, 0xac))
	return &s
}

// paidTx is a transaction spending each source's output 0 with a 107-byte
// P2PKH unlock, paying the given scripts and a P2PKH change output.
func paidTx(sources []*transaction.Transaction, locks ...*script.Script) *transaction.Transaction {
	tx := transaction.NewTransaction()
	for _, src := range sources {
		unlock := script.Script(make([]byte, 107))
		tx.AddInput(&transaction.TransactionInput{
			SourceTXID: src.TxID(), SourceTxOutIndex: 0, SourceTransaction: src,
			UnlockingScript: &unlock, SequenceNumber: 0xffffffff,
		})
	}
	for _, l := range locks {
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: l, Satoshis: 1})
	}
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: p2pkhScript(), Satoshis: 1000})
	return tx
}

// parentTx is a distinct, already-mined transaction paying P2PKH outputs.
func parentTx(id uint64, outputs int) *transaction.Transaction {
	tx := transaction.NewTransaction()
	src := chainhash.Hash(node(id, 77))
	unlock := script.Script(make([]byte, 107))
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &src, UnlockingScript: &unlock, SequenceNumber: 0xffffffff})
	for i := 0; i < outputs; i++ {
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: p2pkhScript(), Satoshis: 1000})
	}
	return tx
}

// blockProofs gives each txid a proof in one block of 2^height transactions,
// at the given offsets, all against the same root: a node off every path is
// pseudo-random and a node on one is the hash of its children.
func blockProofs(block uint32, height int, txids []*chainhash.Hash, offsets []uint64) []*transaction.MerklePath {
	type key struct {
		h int
		o uint64
	}
	memo := map[key]*chainhash.Hash{}
	owner := map[key]int{}
	for i, o := range offsets {
		for h := 0; h <= height; h++ {
			owner[key{h, o >> h}] = i + 1
		}
	}
	var get func(h int, o uint64) *chainhash.Hash
	get = func(h int, o uint64) *chainhash.Hash {
		k := key{h, o}
		if v, ok := memo[k]; ok {
			return v
		}
		var v *chainhash.Hash
		switch i, on := owner[k]; {
		case !on:
			x := chainhash.Hash(node(uint64(block)<<8|uint64(h), o))
			v = &x
		case h == 0:
			v = txids[i-1]
		default:
			v = transaction.MerkleTreeParent(get(h-1, 2*o), get(h-1, 2*o+1))
		}
		memo[k] = v
		return v
	}
	isTxid := true
	paths := make([]*transaction.MerklePath, len(txids))
	for i, o := range offsets {
		path := make([][]*transaction.PathElement, height)
		self := &transaction.PathElement{Offset: o, Hash: txids[i], Txid: &isTxid}
		sib := &transaction.PathElement{Offset: o ^ 1, Hash: get(0, o^1)}
		path[0] = []*transaction.PathElement{self, sib}
		if o&1 == 1 {
			path[0] = []*transaction.PathElement{sib, self}
		}
		for h := 1; h < height; h++ {
			path[h] = []*transaction.PathElement{{Offset: (o >> h) ^ 1, Hash: get(h, (o>>h)^1)}}
		}
		paths[i] = transaction.NewMerklePath(block, path)
	}
	return paths
}

// mined gives tx a proof of its own in its own block.
func mined(tx *transaction.Transaction, block uint32) *transaction.Transaction {
	offset := uint64(block)*7919%(1<<blockTreeHeight) | 1
	tx.MerklePath = blockProofs(block, blockTreeHeight, []*chainhash.Hash{tx.TxID()}, []uint64{offset})[0]
	return tx
}

// encodings returns tx's BEEF as V1, V2 and Atomic. Each call to build must
// return fresh transactions: Transaction.BEEF combines proofs in place.
func encodings(t *testing.T, build func() *transaction.Transaction) map[string][]byte {
	t.Helper()
	v1, err := build().BEEF()
	if err != nil {
		t.Fatalf("BEEF: %v", err)
	}
	tx := build()
	b := transaction.NewBeefV2()
	if _, err = b.MergeTransaction(tx); err != nil {
		t.Fatalf("MergeTransaction: %v", err)
	}
	b.NewestTxID = tx.TxID()
	v2, err := b.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	at, err := build().AtomicBEEF(false)
	if err != nil {
		t.Fatalf("AtomicBEEF: %v", err)
	}
	return map[string][]byte{"V1": v1, "V2": v2, "Atomic": at}
}

func protoWallet(t *testing.T) (*wallet.CompletedProtoWallet, *ec.PrivateKey) {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	w, err := wallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatalf("NewCompletedProtoWallet: %v", err)
	}
	return w, priv
}

func pushDropLock(t *testing.T, w wallet.Interface, fields [][]byte, proto wallet.Protocol, keyID string, cp wallet.Counterparty, forSelf, sign bool) *script.Script {
	t.Helper()
	s, err := (&pushdrop.PushDrop{Wallet: w}).Lock(context.Background(), fields, proto, keyID, cp, forSelf, sign, pushdrop.LockBefore)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	return s
}

// adLocks are a SHIP and a SLAP advertisement as Anvil's advertiser locks
// them: the WalletAdvertiser recipe, counterparty anyone and forSelf.
func adLocks(t *testing.T) []*script.Script {
	t.Helper()
	w, priv := protoWallet(t)
	identity := priv.PubKey().Compressed()
	anyone := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}
	var locks []*script.Script
	for _, ad := range []struct {
		proto overlay.Protocol
		name  string
	}{
		{overlay.ProtocolSHIP, "tm_uhrp"}, {overlay.ProtocolSLAP, "ls_uhrp"},
	} {
		proto := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: string(ad.proto.ID())}
		fields := [][]byte{[]byte(ad.proto), identity, []byte("https://anvil.example.com"), []byte(ad.name)}
		locks = append(locks, pushDropLock(t, w, fields, proto, "1", anyone, true, true))
	}
	return locks
}

// umpLock is a v3 UMP token of 15 fields, as topics/ump_test.go builds it.
func umpLock(t *testing.T) *script.Script {
	t.Helper()
	w, _ := protoWallet(t)
	fields := [][]byte{{1}, {2}, {3}, {4}, {5}, {6}, make([]byte, 32), make([]byte, 32), {9}, {10}, {11},
		{12, 13, 14}, {3}, []byte("PBKDF2-SHA512"), []byte(`{"iterations":3}`)}
	proto := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: "admin user management token"}
	return pushDropLock(t, w, fields, proto, "1", wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}, false, false)
}

// kvLock is a signed, tagged KVStore token, as topics/kvstore_test.go builds
// it.
func kvLock(t *testing.T) *script.Script {
	t.Helper()
	w, priv := protoWallet(t)
	proto := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "sendbsv settings"}
	protoJSON, _ := json.Marshal(&proto)
	tags, _ := json.Marshal([]string{"theme"})
	fields := [][]byte{protoJSON, []byte("theme"), []byte(`{"mode":"dark"}`), priv.PubKey().Compressed(), tags}
	return pushDropLock(t, w, fields, proto, "theme", wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}, false, true)
}

func ordLock(t *testing.T) *script.Script {
	t.Helper()
	b, err := hex.DecodeString(tvznOrdLock)
	if err != nil {
		t.Fatalf("decode OrdLock: %v", err)
	}
	s := script.Script(b)
	return &s
}

// legitimate returns every honest fixture, by name, in each encoding.
func legitimate(t *testing.T) map[string][]byte {
	t.Helper()
	ads, ump, kv, ol := adLocks(t), umpLock(t), kvLock(t), ordLock(t)
	fixtures := map[string]func() *transaction.Transaction{
		"SHIP and SLAP advertisements": func() *transaction.Transaction {
			return paidTx([]*transaction.Transaction{mined(parentTx(1, 1), 900001)}, ads...)
		},
		"DEX OrdLock listing": func() *transaction.Transaction {
			srcs := []*transaction.Transaction{mined(parentTx(2, 1), 900002), mined(parentTx(3, 1), 900003)}
			return paidTx(srcs, ol)
		},
		"UMP token": func() *transaction.Transaction {
			return paidTx([]*transaction.Transaction{mined(parentTx(4, 1), 900004)}, ump)
		},
		"KVStore token": func() *transaction.Transaction {
			return paidTx([]*transaction.Transaction{mined(parentTx(5, 1), 900005)}, kv)
		},
		"chain of 1,000 unproven from one proven root": func() *transaction.Transaction {
			tx := mined(parentTx(6, 1), 900006)
			for i := 0; i < 1000; i++ {
				tx = paidTx([]*transaction.Transaction{tx})
			}
			return tx
		},
		"1,000 inputs from distinct blocks": func() *transaction.Transaction {
			srcs := make([]*transaction.Transaction, 1000)
			for i := range srcs {
				srcs[i] = mined(parentTx(uint64(1000+i), 2), uint32(800000+i))
			}
			return paidTx(srcs)
		},
		"100 inputs from one block": func() *transaction.Transaction {
			srcs := make([]*transaction.Transaction, 100)
			txids := make([]*chainhash.Hash, 100)
			offsets := make([]uint64, 100)
			for i := range srcs {
				srcs[i] = parentTx(uint64(5000+i), 2)
				txids[i] = srcs[i].TxID()
				offsets[i] = uint64(i) * 10487 % (1 << blockTreeHeight)
			}
			for i, p := range blockProofs(900100, blockTreeHeight, txids, offsets) {
				srcs[i].MerklePath = p
			}
			return paidTx(srcs)
		},
	}
	out := map[string][]byte{}
	for name, build := range fixtures {
		for enc, b := range encodings(t, build) {
			out[name+", "+enc] = b
		}
	}
	return out
}
