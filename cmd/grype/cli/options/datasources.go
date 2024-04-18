package options

import (
	"github.com/anchore/grype/grype/matcher/java"
)

const (
	defaultMavenBaseURL = "https://search.maven.org/solrsearch/select"
	defaultAbortAfter   = "10m"
)

type externalSources struct {
	Enable     bool   `yaml:"enable" json:"enable" mapstructure:"enable"`
	AbortAfter string `yaml:"abort-after" json:"abortAfter" mapstructure:"abort-after"`
	Maven      maven  `yaml:"maven" json:"maven" mapstructure:"maven"`
}

type maven struct {
	SearchUpstreamBySha1 bool    `yaml:"search-upstream" json:"searchUpstreamBySha1" mapstructure:"search-maven-upstream"`
	BaseURL              string  `yaml:"base-url" json:"baseUrl" mapstructure:"base-url"`
	AbortAfter           *string `yaml:"abort-after" json:"abortAfter" mapstructure:"abort-after"`
}

func defaultExternalSources() externalSources {
	return externalSources{
		AbortAfter: defaultAbortAfter,
		Maven: maven{
			SearchUpstreamBySha1: true,
			BaseURL:              defaultMavenBaseURL,
		},
	}
}

func (cfg externalSources) ToJavaMatcherConfig() java.ExternalSearchConfig {
	// always respect if global config is disabled
	smu := cfg.Maven.SearchUpstreamBySha1
	if !cfg.Enable {
		smu = cfg.Enable
	}

	abortAfter := cfg.AbortAfter
	if cfg.Maven.AbortAfter != nil {
		abortAfter = *cfg.Maven.AbortAfter
	}

	return java.ExternalSearchConfig{
		SearchMavenUpstream: smu,
		MavenBaseURL:        cfg.Maven.BaseURL,
		AbortAfter:          abortAfter,
	}
}
