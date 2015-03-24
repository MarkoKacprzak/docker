// +build windows

// Shim for Windows Containers Host Compute Service (HSC)
// This file contains the storage specific shim function calls.

package hcsshim

import (
	"errors"
	"syscall"
	"unsafe"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/guid"
)

const (
	PROCATTACHFILTER = "AttachStorageFilter"
	PROCDETACHFILTER = "DetachStorageFilter"
	PROCINITSANDBOX  = "InitializeStorageSandbox"
)

/* To pass into syscall, we need a struct matching the following:
typedef struct _WC_LAYER_DESCRIPTOR {

    //
    // The ID of the layer
    //

    GUID LayerId;

    //
    // Additional flags
    //

    union {
        struct {
            ULONG Reserved : 31;
            ULONG Dirty : 1;    // Created from sandbox as a result of snapshot
        };
        ULONG Value;
    } Flags;

    //
    // Path to the layer root directory, null-terminated
    //

    PCWSTR Path;

} WC_LAYER_DESCRIPTOR, *PWC_LAYER_DESCRIPTOR;
*/
type WC_LAYER_DESCRIPTOR struct {
	LayerId guid.Guid
	Flags   uint32
	Pathp   *uint16
}

func InitializeStorageSandbox(sandboxPath string, parentLayerPaths []string) error {
	log.Debugln("hcsshim::InitializeStorageSandbox")
	log.Debugln("sandboxPath:", sandboxPath)
	log.Debugln("parentLayerPaths:", parentLayerPaths)

	var (
		// Arguments to the call.
		sandboxPathp      *uint16
		layerDescriptorsp *WC_LAYER_DESCRIPTOR

		// Array of descriptors that gets constructed.
		layers []WC_LAYER_DESCRIPTOR

		// Result values from calling the procedure
		r1, r2 uintptr

		// The DLL and procedure in the DLL respectively
		dll  *syscall.DLL
		proc *syscall.Proc

		// Error tracking
		err error
	)

	for i := 0; i < len(parentLayerPaths); i++ {
		// Create a layer descriptor, using the folder path
		// as the source for a GUID LayerId
		g := guid.NewGuid(parentLayerPaths[i])

		p, err := syscall.UTF16PtrFromString(parentLayerPaths[i])
		if err != nil {
			log.Debugln("Failed conversion of parentLayerPath to pointer ", err)
			return err
		}

		layers = append(layers, WC_LAYER_DESCRIPTOR{
			LayerId: *g,
			Flags:   0,
			Pathp:   p,
		})
	}

	sandboxPathp, err = syscall.UTF16PtrFromString(sandboxPath)
	if err != nil {
		log.Debugln("Failed conversion of sandboxPath to pointer ", err)
		return err
	}

	layerDescriptorsp = &(layers[0])

	// Load the DLL and get the function
	dll, proc, err = loadAndFind(PROCINITSANDBOX)

	// Release once used if we managed to get a handle to it
	if dll != nil {
		defer dll.Release()
	}

	// Call the procedure itself.
	r1, r2, err = proc.Call(
		uintptr(unsafe.Pointer(sandboxPathp)),
		uintptr(unsafe.Pointer(layerDescriptorsp)),
		uintptr(len(layers)))

	// Check the result codes first
	if r1 != 0 || r2 != 0 {
		log.Debugln("r1 ", r1)
		return errors.New(PROCINITSANDBOX + " failed r1/r2 check")
	}

	// Check for error itself next
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			return errors.New(PROCINITSANDBOX + " failed. " + err.Error())
		}
	}

	return nil
}
