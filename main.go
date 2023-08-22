package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go FileProtector bpf/lsm.c -- -I./bpf -O2

/*
#include <time.h>
static unsigned long long get_nsecs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"

const ( // bpf2go cannot restore enum to corresponding names. so i do it manually
	FileProtectorFileProtectStateEnabled FileProtectorFileProtectState = iota
	FileProtectorFileProtectStateTick
	FileProtectorFileProtectStateMax
)

const (
	FileProtectorFilePathDisabled uint8 = iota
	FileProtectorFilePathEnabled
)

const (
	// pin path
	PinPath     = "/sys/fs/bpf/file_protector"
	LinkPinPath = PinPath + "/link_file_open"
)

func main() {
	fDebug := flag.Bool("debug", false, "toggle to show full ebpf verifier error")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	if err := os.MkdirAll(PinPath, os.ModePerm); err != nil {
		log.Printf("W: failed to create ebpf pin path: %v. directory will not be protected if userspace daemon exited", err)
	} else {
		log.Printf("ebpf pin path is ensured to be a directory: %v", PinPath)
	}

	fileProtectorObjects := FileProtectorObjects{}
	if err := LoadFileProtectorObjects(&fileProtectorObjects, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 1024,
		},
		Maps: ebpf.MapOptions{
			PinPath: PinPath,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if *fDebug && errors.As(err, &ve) {
			// Using %+v will print the whole verifier error, not just the last
			// few lines.
			fmt.Printf("Verifier error: %+v\n", ve)
		}
		log.Panic("failed to attach lsm: ", err)
	}
	defer fileProtectorObjects.Close()
	log.Println("lsm loaded")

	progLink, err := link.LoadPinnedLink(LinkPinPath, nil)
	if err != nil {
		log.Printf("failed load pinned link(%s): %v. trying to attach the program", LinkPinPath, err)
		progLink, err = link.AttachLSM(link.LSMOptions{
			Program: fileProtectorObjects.CheckFileOpen,
		})
		if err != nil {
			log.Panic("failed to attach lsm: ", err)
		}
		log.Println("lsm attached")

		if err := progLink.Pin(LinkPinPath); err != nil {
			log.Printf("W: failed to pin program: %v. ebpf will not survive after daemon exits.", err)
		} else {
			log.Printf("link pinned to %v", LinkPinPath)
		}
		log.Printf("to decrease refcount to release objects, simply run: sudo rm -r %v", PinPath)
	} else {
		log.Printf("lsm link loaded from existing pinned objects(%v)", LinkPinPath)
	}
	defer progLink.Close()

	log.Println("configure maps...")
	newRoots := make(map[uint64]string)
	for _, path := range flag.Args() {
		path, _ = filepath.Abs(path)
		log.Println("-", path)
		stat, err := os.Stat(path)
		if err != nil {
			log.Println("W: ", err)
			continue
		}
		switch stat := stat.Sys().(type) {
		case *syscall.Stat_t:
			if err := fileProtectorObjects.FileProtectorMaps.Roots.Update(stat.Ino, FileProtectorFilePathEnabled, ebpf.UpdateAny); err != nil {
				panic(err)
			}
			newRoots[stat.Ino] = path
		default:
			log.Printf("W: incompatible type of stat: %T", stat)
			continue
		}
	}

	var (
		inoKey     uint64
		inoEnabled uint8
	)
	iter := fileProtectorObjects.Roots.Iterate()
	for iter.Next(&inoKey, &inoEnabled) {
		if path, ok := newRoots[inoKey]; ok && inoEnabled == FileProtectorFilePathEnabled {
			log.Printf("disabling root: %v(%v)", path, inoKey)
			if err := fileProtectorObjects.Roots.Update(inoKey, FileProtectorFilePathDisabled, 0); err != nil {
				log.Printf("W: failed to update root table when disable root: %v", err)
			}
		}
	}
	// TODO: you should also protect the daemon config itself

	log.Println("configuration done. enabling...")

	if err := fileProtectorObjects.FileProtectorMaps.States.Update(FileProtectorFileProtectStateEnabled, uint64(1), ebpf.UpdateAny); err != nil {
		panic(err)
	}

	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()
	log.Println("ticking...but with one step slower intentionally!")
	prevBannedAccesses := make(map[uint64]uint64)
	for {
		now := uint64(C.get_nsecs())
		// TODO: read and show perf data

		perf := ""
		bannedAccesses := fileProtectorObjects.BannedAccess.Iterate()
		var (
			bannedRoot, counter uint64
		)
		for bannedAccesses.Next(&bannedRoot, &counter) {
			name := fmt.Sprintf("inode(%v)", bannedRoot)

			if path, ok := newRoots[bannedRoot]; ok {
				name = path
			}
			if prevCounter, ok := prevBannedAccesses[bannedRoot]; ok {
				if counter-prevCounter > 0 {
					perf += fmt.Sprintf(" %v=+%v", name, counter-prevCounter)
				}
			} else {
				perf += fmt.Sprintf(" %v=%v", name, counter)
			}
			prevBannedAccesses[bannedRoot] = counter
		}

		log.Printf("tick:%v%v", now, perf)

		if err := fileProtectorObjects.FileProtectorMaps.States.Update(FileProtectorFileProtectStateTick, uint64(now), ebpf.UpdateAny); err != nil {
			panic(err)
		}

		<-ticker.C
	}
}
