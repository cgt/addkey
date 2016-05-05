// Copyright Christoffer G. Thomsen 2016
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

// Command addkey adds a public key to an LXD container's root authorized_keys.
//
// By default, addkey will use $HOME/.ssh/id_rsa.pub.
// Using the `-i PUBKEYFILE` flag will make it copy the specified key instead.
package main // import "cgt.name/pkg/addkey"

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"

	"golang.org/x/crypto/ssh"
)

// perr prints an error to stderr
func perr(e error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", e)
}

// rmTmpFile closes and deletes a file.
func rmFile(f *os.File) {
	err := f.Close()
	if err != nil {
		perr(fmt.Errorf("error closing temp file: %v\n", err))
	}
	err = os.Remove(f.Name())
	if err != nil {
		perr(fmt.Errorf("error deleting temp file: %v\n", err))
	}
}

// lxcPull uses the `lxc file pull` command to retrieve a file from a container.
func lxcPull(dstPath, srcPath string) error {
	pull := exec.Command("lxc", "file", "pull", srcPath, dstPath)
	err := pull.Run()
	if err != nil {
		return err
	}
	return nil
}

// lxcPush uses the `lxc file push` command to copy a file to a container.
// The file will be owned by root:root with permissions 640 inside the container.
func lxcPush(dstPath, srcPath string) error {
	push := exec.Command("lxc", "file", "push", "--uid=0", "--gid=0", "--mode=640", srcPath, dstPath)
	err := push.Run()
	if err != nil {
		return err
	}
	return nil
}

type authKey struct {
	Key     ssh.PublicKey
	Comment string
}

func (k authKey) MarshalWithComment() []byte {
	var buf bytes.Buffer
	buf.Write(bytes.TrimSpace(ssh.MarshalAuthorizedKey(k.Key)))
	buf.WriteByte(' ')
	buf.WriteString(k.Comment)
	buf.WriteByte('\n')
	return buf.Bytes()
}

var errUnsupportedKeyAlgo = fmt.Errorf("unsupported key algorithm. Supported algorithms: %s, %s, %s, %s, %s.",
	ssh.KeyAlgoRSA,
	ssh.KeyAlgoDSA,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
)

func parseAuthKey(line []byte) (authKey, error) {
	supported := false

	if bytes.HasPrefix(line, []byte(ssh.KeyAlgoRSA)) {
		supported = true
	} else if bytes.HasPrefix(line, []byte(ssh.KeyAlgoDSA)) {
		supported = true
	} else if bytes.HasPrefix(line, []byte(ssh.KeyAlgoECDSA256)) {
		supported = true
	} else if bytes.HasPrefix(line, []byte(ssh.KeyAlgoECDSA384)) {
		supported = true
	} else if bytes.HasPrefix(line, []byte(ssh.KeyAlgoECDSA521)) {
		supported = true
	}

	if !supported {
		return authKey{}, errUnsupportedKeyAlgo
	}

	key, comment, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return authKey{}, fmt.Errorf("error parsing key: %v", err)
	}
	return authKey{key, comment}, nil
}

// readAuthorizedKeys reads public keys in the ssh authorized_keys format from
// and io.Reader into `authKey`s and returns a slice of authKey.
func readAuthorizedKeys(r io.Reader) ([]authKey, error) {
	var keys []authKey

	rr := bufio.NewReader(r)
	for {
		line, err := rr.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		key, err := parseAuthKey(line)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

func writeAuthorizedKeys(f *os.File, keys []authKey, dstPath string) error {
	if len(keys) == 0 {
		return errors.New("no keys to write")
	}

	err := f.Truncate(0)
	if err != nil {
		return err
	}
	f.Seek(0, 0)

	w := bufio.NewWriter(f)
	for _, k := range keys {
		_, err = w.Write(k.MarshalWithComment())
		if err != nil {
			return err
		}
	}

	err = w.Flush()
	if err != nil {
		return err
	}

	err = lxcPush(dstPath, f.Name())
	if err != nil {
		return err
	}

	return nil
}

func realmain(container string, keyFlag *string) error {
	// Get key to add to authorized_keys.
	var keyPath string
	if len(*keyFlag) != 0 {
		keyPath = *keyFlag
	} else {
		keyPath = os.ExpandEnv("$HOME/.ssh/id_rsa.pub")
	}

	keybuf, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("error reading key: %v", err)
	}

	key, err := parseAuthKey(keybuf)
	if err != nil {
		return err
	}

	tmp, err := ioutil.TempFile("", "addkey")
	if err != nil {
		return err
	}
	defer rmFile(tmp)

	// Read root authorized_keys from container.
	authKeysPath := fmt.Sprintf("%s/root/.ssh/authorized_keys", container)
	err = lxcPull(tmp.Name(), authKeysPath)
	if err != nil {
		return err
	}

	keys, err := readAuthorizedKeys(tmp)
	if err != nil {
		return err
	}

	// Check that key to add isn't already in authorized_keys.
	keymarshal := key.Key.Marshal()
	for _, k := range keys {
		if bytes.Compare(keymarshal, k.Key.Marshal()) == 0 {
			return fmt.Errorf("key already in authorized_keys")
		}
	}

	// Write authorized_keys with new key
	keys = append(keys, key)
	err = writeAuthorizedKeys(tmp, keys, authKeysPath)
	if err != nil {
		return fmt.Errorf("error pushing new authorized_keys: %v", err)
	}

	return nil
}

// main parses flags/args and passes them to realmain.
// If realmain returns a non-nil error, main prints the error to stderr and
// exits with code 1.
func main() {
	keyFlag := flag.String("i", "", "specify public key file to use")
	flag.Parse()

	container := flag.Arg(0)
	if len(container) == 0 {
		printUsage()
		os.Exit(1)
	}

	err := realmain(container, keyFlag)
	if err != nil {
		perr(err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "usage: %s [OPTIONS] <container>\n", os.Args[0])
	flag.PrintDefaults()
}
