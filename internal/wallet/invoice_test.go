package wallet

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

func TestInvoiceSaveAndLoad(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-invoice-*")
	t.Cleanup(func() { os.RemoveAll(dir) })

	db, err := leveldb.OpenFile(dir+"/invoices", nil)
	if err != nil {
		t.Fatal(err)
	}

	inv := &Invoice{
		ID:           "42",
		Address:      "1TestAddr",
		PublicKey:    "02abcdef",
		Description:  "test invoice",
		Counterparty: "03aabbcc",
		Protocol:     "invoice payment",
		KeyID:        "42",
	}

	// Save
	data, _ := json.Marshal(inv)
	if err := db.Put([]byte(inv.ID), data, nil); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Re-open (simulates restart)
	db2, err := leveldb.OpenFile(dir+"/invoices", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	// Load
	raw, err := db2.Get([]byte("42"), nil)
	if err != nil {
		t.Fatalf("invoice not found after re-open: %v", err)
	}

	var loaded Invoice
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.ID != "42" {
		t.Fatalf("expected id 42, got %s", loaded.ID)
	}
	if loaded.Address != "1TestAddr" {
		t.Fatalf("expected address 1TestAddr, got %s", loaded.Address)
	}
	if loaded.Counterparty != "03aabbcc" {
		t.Fatalf("expected counterparty 03aabbcc, got %s", loaded.Counterparty)
	}

	t.Log("invoice persistence across restart: pass")
}

func TestInvoiceIDRecovery(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-invoice-recovery-*")
	t.Cleanup(func() { os.RemoveAll(dir) })

	db, err := leveldb.OpenFile(dir+"/invoices", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate 5 invoices written before a "crash"
	for i := 1; i <= 5; i++ {
		inv := &Invoice{ID: json.Number(json.Number(string(rune('0' + i)))).String()}
		data, _ := json.Marshal(inv)
		db.Put([]byte(inv.ID), data, nil)
	}
	db.Close()

	// Re-open and recover max ID
	db2, err := leveldb.OpenFile(dir+"/invoices", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	maxID := 0
	iter := db2.NewIterator(nil, nil)
	for iter.Next() {
		key := string(iter.Key())
		if id := 0; true {
			for _, c := range key {
				if c >= '0' && c <= '9' {
					id = id*10 + int(c-'0')
				}
			}
			if id > maxID {
				maxID = id
			}
		}
	}
	iter.Release()

	if maxID != 5 {
		t.Fatalf("expected recovered maxID=5, got %d", maxID)
	}

	t.Log("invoice ID recovery after restart: pass")
}

func TestInvoiceNotFound(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-invoice-notfound-*")
	t.Cleanup(func() { os.RemoveAll(dir) })

	db, err := leveldb.OpenFile(dir+"/invoices", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Get([]byte("nonexistent"), nil)
	if err == nil {
		t.Fatal("expected error for nonexistent invoice")
	}
}
