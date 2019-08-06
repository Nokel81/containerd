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

package remotes

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// MakeRefKey returns a unique reference for the descriptor. This reference can be
// used to lookup ongoing processes related to the descriptor. This function
// may look to the context to namespace the reference appropriately.
func MakeRefKey(ctx context.Context, desc ocispec.Descriptor) string {
	// TODO(stevvooe): Need better remote key selection here. Should be a
	// product of the context, which may include information about the ongoing
	// fetch process.
	switch desc.MediaType {
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		return "manifest-" + desc.Digest.String()
	case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		return "index-" + desc.Digest.String()
	case images.MediaTypeDockerSchema2Layer, images.MediaTypeDockerSchema2LayerGzip,
		images.MediaTypeDockerSchema2LayerForeign, images.MediaTypeDockerSchema2LayerForeignGzip,
		ocispec.MediaTypeImageLayer, ocispec.MediaTypeImageLayerGzip,
		ocispec.MediaTypeImageLayerNonDistributable, ocispec.MediaTypeImageLayerNonDistributableGzip,
		images.MediaTypeDockerSchema2LayerEnc, images.MediaTypeDockerSchema2LayerGzipEnc:
		return "layer-" + desc.Digest.String()
	case images.MediaTypeDockerSchema2Config, ocispec.MediaTypeImageConfig:
		return "config-" + desc.Digest.String()
	default:
		log.G(ctx).Warnf("reference for unknown type: %s", desc.MediaType)
		return "unknown-" + desc.Digest.String()
	}
}

// FetchHandler returns a handler that will fetch all content into the ingester
// discovered in a call to Dispatch. Use with ChildrenHandler to do a full
// recursive fetch.
func FetchHandler(ingester content.Ingester, fetcher Fetcher) images.FindHandler {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		ctx = log.WithLogger(ctx, log.G(ctx).WithFields(logrus.Fields{
			"digest":    desc.Digest,
			"mediatype": desc.MediaType,
			"size":      desc.Size,
		}))

		switch desc.MediaType {
		case images.MediaTypeDockerSchema1Manifest:
			return nil, fmt.Errorf("%v not supported", desc.MediaType)
		default:
			return nil, fetch(ctx, ingester, fetcher, desc)
		}
	}
}

func fetch(ctx context.Context, ingester content.Ingester, fetcher Fetcher, desc ocispec.Descriptor) error {
	log.G(ctx).Debug("fetch")

	cw, err := content.OpenWriter(ctx, ingester, content.WithRef(MakeRefKey(ctx, desc)), content.WithDescriptor(desc))
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	defer cw.Close()

	ws, err := cw.Status()
	if err != nil {
		return err
	}

	if ws.Offset == desc.Size {
		// If writer is already complete, commit and return
		err := cw.Commit(ctx, desc.Size, desc.Digest)
		if err != nil && !errdefs.IsAlreadyExists(err) {
			return errors.Wrapf(err, "failed commit on ref %q", ws.Ref)
		}
		return nil
	}

	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer rc.Close()

	return content.Copy(ctx, cw, rc, desc.Size, desc.Digest)
}

// PushHandler returns a handler that will push all content from the provider
// using a writer from the pusher.
func PushHandler(m sync.Mutex, manifestStack []ocispec.Descriptor, pusher Pusher, provider content.Provider) images.ObserveHandler {
	return func(ctx context.Context, parent ocispec.Descriptor, children []ocispec.Descriptor) error {
		switch parent.MediaType {
		case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest,
			images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
			m.Lock()
			manifestStack = append(manifestStack, parent)
			m.Unlock()
			return nil
		default:
			ctx = log.WithLogger(ctx, log.G(ctx).WithFields(logrus.Fields{
				"digest":    parent.Digest,
				"mediatype": parent.MediaType,
				"size":      parent.Size,
			}))

			return push(ctx, provider, pusher, parent)
		}
	}
}

func push(ctx context.Context, provider content.Provider, pusher Pusher, desc ocispec.Descriptor) error {
	log.G(ctx).Debug("push")

	cw, err := pusher.Push(ctx, desc)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}

		return err
	}
	defer cw.Close()

	ra, err := provider.ReaderAt(ctx, desc)
	if err != nil {
		return err
	}
	defer ra.Close()

	rd := io.NewSectionReader(ra, 0, desc.Size)
	return content.Copy(ctx, cw, rd, desc.Size, desc.Digest)
}

// PushContent pushes content specified by the descriptor from the provider.
//
// Base handlers can be provided which will be called before any push specific
// handlers.
func PushContent(ctx context.Context, pusher Pusher, desc ocispec.Descriptor, store content.Store, platform platforms.MatchComparer) error {
	var m sync.Mutex
	var manifestStack []ocispec.Descriptor
	var handlerBundle images.Handlers

	pushHandler := PushHandler(m, manifestStack, pusher, store)

	handlerBundle.Add(images.ChildrenHandler(store))
	handlerBundle.Add(images.FilterPlatforms(platform))
	handlerBundle.Add(annotateDistributionSourceHandler(store))
	handlerBundle.Add(pushHandler)

	if err := images.Dispatch(ctx, handlerBundle.Build(), nil, desc); err != nil {
		return err
	}

	// Iterate in reverse order as seen, parent always uploaded after child
	for i := len(manifestStack) - 1; i >= 0; i-- {
		err := pushHandler(ctx, manifestStack[i], []ocispec.Descriptor{})

		if err != nil {
			// TODO(estesp): until we have a more complete method for index push, we need to report
			// missing dependencies in an index/manifest list by sensing the "400 Bad Request"
			// as a marker for this problem
			if (manifestStack[i].MediaType == ocispec.MediaTypeImageIndex ||
				manifestStack[i].MediaType == images.MediaTypeDockerSchema2ManifestList) &&
				errors.Cause(err) != nil && strings.Contains(errors.Cause(err).Error(), "400 Bad Request") {
				return errors.Wrap(err, "manifest list/index references to blobs and/or manifests are missing in your target registry")
			}

			return err
		}
	}

	return nil
}

// FilterManifestByPlatformHandler allows Handler to handle non-target
// platform's manifest and configuration data.
func FilterManifestByPlatformHandler(m platforms.Matcher) images.FilterHandler {
	if m == nil {
		return nil
	}

	return func(ctx context.Context, parent ocispec.Descriptor, child ocispec.Descriptor, index int) bool {
		if parent.Platform == nil {
			return true
		}

		if parent.MediaType == images.MediaTypeDockerSchema2Manifest || parent.MediaType == ocispec.MediaTypeImageManifest {
			if m.Match(*parent.Platform) {
				return true
			}

			return child.MediaType == images.MediaTypeDockerSchema2Config || child.MediaType == ocispec.MediaTypeImageConfig
		}

		return true
	}
}

// annotateDistributionSourceHandler add distribution source label into
// annotation of config or blob descriptor.
func annotateDistributionSourceHandler(manager content.Manager) images.MapHandler {
	return func(ctx context.Context, parent ocispec.Descriptor, child ocispec.Descriptor, index int) (ocispec.Descriptor, error) {
		// only add distribution source for the config or blob data descriptor
		switch parent.MediaType {
		case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest,
			images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		default:
			return child, nil
		}

		info, err := manager.Info(ctx, child.Digest)
		if err != nil {
			return child, err
		}

		if child.Annotations == nil {
			child.Annotations = map[string]string{}
		}

		for k, v := range info.Labels {
			if !strings.HasPrefix(k, "containerd.io/distribution.source.") {
				continue
			}

			child.Annotations[k] = v
		}

		return child, nil
	}
}
