/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package images

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

var (
	// ErrSkipDesc is used to skip processing of a descriptor and
	// its descendants.
	ErrSkipDesc = fmt.Errorf("skip descriptor")

	// ErrStopHandler is used to signify that the descriptor
	// has been handled and should not be handled further.
	// This applies only to a single descriptor in a handler
	// chain and does not apply to descendant descriptors.
	ErrStopHandler = fmt.Errorf("stop handler")
)

// FindHandler is used to find the children on a descriptor. This is for adding new types of children.
type FindHandler func(ctx context.Context, parent ocispec.Descriptor) ([]ocispec.Descriptor, error)

// SetupHandler is for setting local information about a curtain parent descriptor before any decent through the tree is done
type SetupHandler func(ctx context.Context, parent ocispec.Descriptor) error

// MapHandler is for updating fields on or about the child descriptor
type MapHandler func(ctx context.Context, parent ocispec.Descriptor, child ocispec.Descriptor, index int) (ocispec.Descriptor, error)

// DescSorter is a simplified sorting function that does not depend on indexes just for descriptors
type DescSorter func(left ocispec.Descriptor, right ocispec.Descriptor) bool

// SortHandler should return a sorter that will be used (or no sorter if sorting this layer is not required)
type SortHandler func(ctx context.Context, parent ocispec.Descriptor) DescSorter

// FilterHandler should return true if the child descriptor is to be kept. False if it should be removed
type FilterHandler func(ctx context.Context, parent ocispec.Descriptor, child ocispec.Descriptor, index int) bool

// ObserveHandler is for final observation of a set of children after being found and acted upon
type ObserveHandler func(ctx context.Context, parent ocispec.Descriptor, children []ocispec.Descriptor) error

type CompleteHandler func(ctx context.Context, parent ocispec.Descriptor) ([]ocispec.Descriptor, error)

type Handlers struct {
	// SetupHandlers are a set of handlers which get are called on dispatch.
	// These handlers always get called before any operation specific
	// handlers.
	SetupHandlers []SetupHandler

	// FindHandlers are used to find children of a given descriptor. All children
	// will be collected together. These are run in order.
	FindHandlers []FindHandler

	// MapHandlers add information to each descriptor. These are run in order on
	// each child descriptor.
	MapHandlers []MapHandler

	// SortHandler, if set, will be used to stable sort the elements before any
	// filter handlers are run.
	SortHandler SortHandler

	// FilterHandlers can be used to filter out any unwanted children from being
	// recursed upon. They are run in order but stops as soon as one returns false.
	FilterHandlers []FilterHandler

	// ObserveHandlers is used to observe all children once they are all found.
	ObserveHandlers []ObserveHandler
}

// Add will add a given function to a set of handlers
func (self *Handlers) Add(handler interface{}) {
	if handler == nil {
		return
	}

	switch h := handler.(type) {
	case SetupHandler:
		self.SetupHandlers = append(self.SetupHandlers, h)
	case FindHandler:
		self.FindHandlers = append(self.FindHandlers, h)
	case MapHandler:
		self.MapHandlers = append(self.MapHandlers, h)
	case SortHandler:
		self.SortHandler = h
	case FilterHandler:
		self.FilterHandlers = append(self.FilterHandlers, h)
	case ObserveHandler:
		self.ObserveHandlers = append(self.ObserveHandlers, h)
	default:
		panic(fmt.Sprintf("unexpected type: %s", reflect.TypeOf(handler)))
	}
}

// Build returns a handler that will run the handlers in sequence.
//
// If any of the following handlers return `ErrStopHandler` then the CompleteHandler will return the found
// children so far with a nil error. This is not supported on all handler types to prevent surprising
// actions where only some the individual actions are accomplished:
//
// - Setup
//
// - Find
//
// - Observe
func (handlers Handlers) Build() CompleteHandler {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		// Run all the setup handlers, exiting if any fail
		for _, setup := range handlers.SetupHandlers {
			if err := setup(ctx, desc); err != nil {
				if err == ErrStopHandler {
					return nil, nil
				}

				return nil, err
			}
		}

		var children []ocispec.Descriptor

		// Find all the children
		for _, find := range handlers.FindHandlers {
			found, err := find(ctx, desc)

			if err != nil {
				if err == ErrStopHandler {
					return children, nil
				}

				return nil, err
			}

			children = append(children, found...)
		}

		// Apply all given map functions
		for index, child := range children {
			for _, update := range handlers.MapHandlers {
				updated, err := update(ctx, desc, child, index)

				if err != nil {
					return nil, err
				}

				children[index] = updated
			}
		}

		// If configured sort the found children
		if handlers.SortHandler != nil {
			sorter := handlers.SortHandler(ctx, desc)

			// if nil is returned then this layer should not be sorted
			if sorter != nil {
				sort.SliceStable(children, func(i int, j int) bool {
					return sorter(children[i], children[j])
				})
			}
		}

		var res []ocispec.Descriptor

		// For every child that has been found, check if it should be kept to be recursed through
		for index, child := range children {
			for _, keep := range handlers.FilterHandlers {
				if keep(ctx, desc, child, index) {
					res = append(res, child)
				}
			}
		}

		// Finally, let all observation handlers run
		for _, observer := range handlers.ObserveHandlers {
			if err := observer(ctx, desc, res); err != nil {
				if err == ErrStopHandler {
					break
				}

				return nil, err
			}
		}

		return res, nil
	}
}

// Walk the resources of an image and call the handler for each. If the handler
// decodes the sub-resources for each image,
//
// This differs from dispatch in that each sibling resource is considered
// synchronously.
func Walk(ctx context.Context, handler CompleteHandler, descs ...ocispec.Descriptor) error {
	for _, desc := range descs {
		children, err := handler(ctx, desc)

		if err != nil {
			if errors.Cause(err) == ErrSkipDesc {
				continue // don't traverse the children.
			}

			return err
		}

		if len(children) > 0 {
			if err := Walk(ctx, handler, children...); err != nil {
				return err
			}
		}
	}

	return nil
}

// Dispatch runs the provided handler for content specified by the descriptors.
// If the handler decode subresources, they will be visited, as well.
//
// Handlers for siblings are run in parallel on the provided descriptors. A
// handler may return `ErrSkipDesc` to signal to the dispatcher to not traverse
// any children.
//
// A concurrency limiter can be passed in to limit the number of concurrent
// handlers running. When limiter is nil, there is no limit.
//
// Typically, this function will be used with `FetchHandler`, often composed
// with other handlers.
//
// If any handler returns an error, the dispatch session will be canceled.
func Dispatch(ctx context.Context, handler CompleteHandler, limiter *semaphore.Weighted, descs ...ocispec.Descriptor) error {
	eg, ctx := errgroup.WithContext(ctx)

	for _, desc := range descs {
		desc := desc

		if limiter != nil {
			if err := limiter.Acquire(ctx, 1); err != nil {
				return err
			}
		}

		eg.Go(func() error {
			desc := desc

			children, err := handler(ctx, desc)
			if limiter != nil {
				limiter.Release(1)
			}

			if err != nil {
				if errors.Cause(err) == ErrSkipDesc {
					return nil // don't traverse the children.
				}

				return err
			}

			if len(children) > 0 {
				return Dispatch(ctx, handler, limiter, children...)
			}

			return nil
		})
	}

	return eg.Wait()
}

// ChildrenHandler decodes well-known manifest types and returns their children.
//
// This is useful for supporting recursive fetch and other use cases where you
// want to do a full walk of resources.
//
// One can also replace this with another implementation to allow descending of
// arbitrary types.
func ChildrenHandler(provider content.Provider) FindHandler {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return Children(ctx, provider, desc)
	}
}

// SetChildrenLabels is a handler wrapper which sets labels for the content on
// the children returned by the handler and passes through the children.
// Must follow a handler that returns the children to be labeled.
func SetChildrenLabels(manager content.Manager) MapHandler {
	return func(ctx context.Context, parent ocispec.Descriptor, child ocispec.Descriptor, index int) (ocispec.Descriptor, error) {
		info := content.Info{
			Digest: parent.Digest,
			Labels: map[string]string{
				fmt.Sprintf("containerd.io/gc.ref.content.%d", index): child.Digest.String(),
			},
		}

		fields := []string{fmt.Sprintf("labels.containerd.io/gc.ref.content.%d", index)}

		_, err := manager.Update(ctx, info, fields...)

		return child, err
	}
}

// FilterPlatforms is a handler wrapper which limits the descriptors returned
// based on matching the specified platform matcher.
func FilterPlatforms(m platforms.Matcher) FilterHandler {
	if m == nil {
		return func(ctx context.Context, parent ocispec.Descriptor, child ocispec.Descriptor, index int) bool {
			return true
		}
	}

	return func(ctx context.Context, parent ocispec.Descriptor, child ocispec.Descriptor, index int) bool {
		return parent.Platform == nil || m.Match(*parent.Platform)
	}
}

func SortManifests(m platforms.MatchComparer) SortHandler {
	if m == nil {
		return nil
	}

	return func(ctx context.Context, parent ocispec.Descriptor) DescSorter {
		switch parent.MediaType {
		case ocispec.MediaTypeImageIndex, MediaTypeDockerSchema2ManifestList:
			return func(left ocispec.Descriptor, right ocispec.Descriptor) bool {
				if left.Platform == nil {
					return false
				}

				if right.Platform == nil {
					return true
				}

				return m.Less(*left.Platform, *right.Platform)
			}
		default:
			return nil
		}
	}
}

// LimitManifests is a handler wrapper which filters the manifest descriptors
// returned using the provided platform.
// The results will be ordered according to the comparison operator and
// use the ordering in the manifests for equal matches.
// A limit of 0 or less is considered no limit.
func LimitManifests(max int) FilterHandler {
	if max <= 0 {
		return nil
	}

	return func(ctx context.Context, parent ocispec.Descriptor, child ocispec.Descriptor, index int) bool {
		return index < max
	}
}
