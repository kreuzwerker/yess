package config

type Config struct {
	Parts     uint8 `mapstructure:"parts"`
	Threshold uint8 `mapstructure:"threshold"`
	Verbose   bool  `mapstructure:"verbose"`
}
