package java

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

const (
	sha1Query = `1:"%s"`
)

type Matcher struct {
	MavenSearcher
	cfg MatcherConfig
}

type ExternalSearchConfig struct {
	SearchMavenUpstream bool
	MavenBaseURL        string
	AbortAfter          time.Duration
}

type MatcherConfig struct {
	ExternalSearchConfig
	UseCPEs bool
}

func NewJavaMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
		MavenSearcher: &mavenSearch{
			client:  http.DefaultClient,
			baseURL: cfg.MavenBaseURL,
		},
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.JavaPkg, syftPkg.JenkinsPluginPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.JavaMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match
	if m.cfg.SearchMavenUpstream {
		timeout := m.cfg.AbortAfter
		ctx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, m.cfg.AbortAfter)
			defer cancel()
		}

		upstreamMatches, err := m.matchUpstreamMavenPackages(ctx, store, d, p)
		if err != nil {
			log.Debugf("failed to match against upstream data for %s: %v", p.Name, err)
		} else {
			matches = append(matches, upstreamMatches...)
		}
	}
	criteria := search.CommonCriteria
	if m.cfg.UseCPEs {
		criteria = append(criteria, search.ByCPE)
	}
	criteriaMatches, err := search.ByCriteria(store, d, p, m.Type(), criteria...)
	if err != nil {
		return nil, fmt.Errorf("failed to match by exact package: %w", err)
	}

	matches = append(matches, criteriaMatches...)
	return matches, nil
}

func (m *Matcher) matchUpstreamMavenPackages(ctx context.Context, store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
		for _, digest := range metadata.ArchiveDigests {
			if digest.Algorithm == "sha1" {
				indirectPackage, err := m.GetMavenPackageBySha(ctx, digest.Value)
				if err != nil {
					return nil, err
				}
				indirectMatches, err := search.ByPackageLanguage(store, d, *indirectPackage, m.Type())
				if err != nil {
					return nil, err
				}
				matches = append(matches, indirectMatches...)
			}
		}
	}

	match.ConvertToIndirectMatches(matches, p)

	return matches, nil
}
