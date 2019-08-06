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

package containerd

import (
	"context"

	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/containerd/containerd/remotes/docker/schema1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
)

// Pull downloads the provided content into containerd's content store
// and returns a platform specific image object
func (c *Client) Pull(ctx context.Context, ref string, opts ...RemoteOpt) (Image, error) {
	pullCtx := defaultRemoteContext()
	for _, o := range opts {
		if err := o(c, pullCtx); err != nil {
			return nil, err
		}
	}

	if pullCtx.PlatformMatcher == nil {
		if len(pullCtx.Platforms) > 1 {
			return nil, errors.New("cannot pull multiplatform image locally, try Fetch")
		} else if len(pullCtx.Platforms) == 0 {
			pullCtx.PlatformMatcher = platforms.Default()
		} else {
			p, err := platforms.Parse(pullCtx.Platforms[0])
			if err != nil {
				return nil, errors.Wrapf(err, "invalid platform %s", pullCtx.Platforms[0])
			}

			pullCtx.PlatformMatcher = platforms.Only(p)
		}
	}

	ctx, done, err := c.WithLease(ctx)
	if err != nil {
		return nil, err
	}
	defer done(ctx)

	img, err := c.fetch(ctx, pullCtx, ref, 1)
	if err != nil {
		return nil, err
	}

	i := NewImageWithPlatform(c, img, pullCtx.PlatformMatcher)

	if pullCtx.Unpack {
		if err := i.Unpack(ctx, pullCtx.Snapshotter); err != nil {
			return nil, errors.Wrapf(err, "failed to unpack image on snapshotter %s", pullCtx.Snapshotter)
		}
	}

	return i, nil
}

func (c *Client) fetch(ctx context.Context, rCtx *RemoteContext, ref string, limit int) (images.Image, error) {
	store := c.ContentStore()
	name, desc, err := rCtx.Resolver.Resolve(ctx, ref)
	if err != nil {
		return images.Image{}, errors.Wrapf(err, "failed to resolve reference %q", ref)
	}

	fetcher, err := rCtx.Resolver.Fetcher(ctx, name)
	if err != nil {
		return images.Image{}, errors.Wrapf(err, "failed to get fetcher for %q", name)
	}

	var (
		handlerBundle images.Handlers
		isConvertible bool
		converterFunc func(context.Context, ocispec.Descriptor) (ocispec.Descriptor, error)
		limiter       *semaphore.Weighted
	)

	if desc.MediaType == images.MediaTypeDockerSchema1Manifest && rCtx.ConvertSchema1 {
		schema1Converter := schema1.NewConverter(store, fetcher)
		isConvertible = true

		handlerBundle.Add(schema1Converter)

		converterFunc = func(ctx context.Context, _ ocispec.Descriptor) (ocispec.Descriptor, error) {
			return schema1Converter.Convert(ctx)
		}
	} else {
		handlerBundle.Add(remotes.FetchHandler(store, fetcher))

		// set isConvertible to true if there is application/octet-stream media type
		handlerBundle.Add(images.SetupHandler(func(ctx context.Context, parent ocispec.Descriptor) error {
			isConvertible = isConvertible || desc.MediaType == docker.LegacyConfigMediaType

			return nil
		}))

		// Get all the children for a descriptor
		handlerBundle.Add(images.ChildrenHandler(store))
		// Set any children labels for that content
		handlerBundle.Add(images.SetChildrenLabels(store))
		// Filter manifests by platforms but allow to handle manifest
		// and configuration for not-target platforms
		handlerBundle.Add(remotes.FilterManifestByPlatformHandler(rCtx.PlatformMatcher))

		// Sort and limit manifests if a finite number is needed
		if limit > 0 {
			handlerBundle.Add(images.SortManifests(rCtx.PlatformMatcher))
			handlerBundle.Add(images.LimitManifests(limit))
		}

		// append distribution source label to blob data
		if rCtx.AppendDistributionSourceLabel {
			appendDistSrcLabelHandler, err := docker.AppendDistributionSourceLabel(store, ref)
			if err != nil {
				return images.Image{}, err
			}

			handlerBundle.Add(appendDistSrcLabelHandler)
		}

		converterFunc = func(ctx context.Context, desc ocispec.Descriptor) (ocispec.Descriptor, error) {
			return docker.ConvertManifest(ctx, store, desc)
		}
	}

	if rCtx.MaxConcurrentDownloads > 0 {
		limiter = semaphore.NewWeighted(int64(rCtx.MaxConcurrentDownloads))
	}

	if err := images.Dispatch(ctx, handlerBundle.Build(), limiter, desc); err != nil {
		return images.Image{}, err
	}

	if isConvertible {
		if desc, err = converterFunc(ctx, desc); err != nil {
			return images.Image{}, err
		}
	}

	img := images.Image{
		Name:   name,
		Target: desc,
		Labels: rCtx.Labels,
	}

	is := c.ImageService()
	for {
		created, err := is.Create(ctx, img)

		if err == nil {
			return created, nil
		}

		if !errdefs.IsAlreadyExists(err) {
			return images.Image{}, err
		}

		updated, err := is.Update(ctx, img)
		if err == nil {
			return updated, nil
		}

		// if image was removed, try create again
		if errdefs.IsNotFound(err) {
			continue
		}

		return images.Image{}, err
	}
}
