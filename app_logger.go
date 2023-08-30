package app_logger

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"

	"github.com/igulib/app"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	AppLoggerUnitName = "app_logger"
)

// Errors
var (
	ErrBadTimeFormat = errors.New("bad log time format, must be one of [none, RFC1123, RFC1123Z, RFC3339, RFC3339Nano, RFC822, RFC822Z, RFC850, RubyDate, Unix, UnixMs, UnixMicro, UnixNano]")

	ErrBadLogLevel = errors.New("bad log level, must be one of [disabled, trace, debug, info, warning, error, fatal, panic]")

	ErrLogFileNotSpecified = errors.New("log file not specified")

	ErrBadFilePermissions = errors.New("bad file permissions")

	ErrBadDirPermissions = errors.New("bad directory permissions")

	ErrBadTelegramBotToken = errors.New("bad telegram bot token")

	ErrBadTelegramChatId = errors.New("bad telegram chat ID")

	ErrLogTelegramConfigIsNil = errors.New("log telegram config is nil")

	ErrLogFileOutputConfigIsNil = errors.New("log file output config is nil")

	ErrLogConsoleOutputConfigIsNil = errors.New("log console output config is nil")
)

var noVal = struct{}{}

var allowedLogLevels = map[string]struct{}{
	"":         noVal,
	"disabled": noVal,
	"trace":    noVal,
	"debug":    noVal,
	"info":     noVal,
	"warning":  noVal,
	"error":    noVal,
	"fatal":    noVal,
	"panic":    noVal,
}

type Config struct {
	// LogLevel must be one of the following:
	// [disabled, trace, debug, info, warning, error, fatal, panic].
	// If not specified, the default log level is "debug".
	LogLevel string `yaml:"log_level" json:"log_level"`

	// TimeFormat must be one of the following:
	// [none, RFC1123, RFC1123Z, RFC3339, RFC3339Nano, RFC822, RFC822Z, RFC850, RubyDate,
	// Unix, UnixMs, UnixMicro, UnixNano].
	// See golang time package documentation for more info about date/time formats.
	// If not specified, the default time format is RFC3339.
	TimeFormat string `yaml:"time_format" json:"time_format"`

	// UseLocalTime allows to use local time instead or UTC.
	// This doesn't have effect if one of the unix timestamp formats is selected as TimeFormat
	// or if TimeFormat is "none".
	// The UTC time is used by default.
	UseLocalTime bool `yaml:"use_local_time" json:"use_local_time"`

	LogFiles []*FileOutputConfig    `yaml:"log_files" json:"log_files"`
	Console  []*ConsoleOutputConfig `yaml:"console" json:"console"`
	Telegram []*TelegramConfig      `yaml:"telegram" json:"telegram"`
}

type validatedConfig struct {
	// LogLevel must be one of the following:
	// [disabled, trace, debug, info, warning, error, fatal, panic].
	// If not specified, the default log level is "debug".
	LogLevel string

	// TimeFormat must be one of the following:
	// [none, RFC1123, RFC1123Z, RFC3339, RFC3339Nano, RFC822, RFC822Z, RFC850, RubyDate,
	// Unix, UnixMs, UnixMicro, UnixNano].
	// See golang time package documentation for more info about date/time formats.
	// If not specified, the default time format is RFC3339.
	TimeFormat string

	// UseLocalTime allows to use local time instead or UTC.
	// This doesn't have effect if one of the unix timestamp formats is selected as TimeFormat
	// or if TimeFormat is "none".
	// The UTC time is used by default.
	UseLocalTime bool

	LogFiles []*validatedFileOutputConfig
	Console  []*validatedConsoleOutputConfig
	Telegram []*validatedTelegramConfig
}

type FileOutputConfig struct {
	// Path is the complete path to the log file,
	// either absolute or relative.
	Path string `yaml:"path" json:"path"`

	// FilePermissions defines the permissions to be applied to the log file,
	// e.g. 0660.
	// If zero, no permissions will be applied.
	FilePermissions uint32 `yaml:"file_permissions" json:"file_permissions"`

	// FilePermissions defines the permissions to be applied to the directory
	// containing the log file.
	// If zero, no permissions will be applied.
	DirPermissions uint32 `yaml:"dir_permissions" json:"dir_permissions"`

	// Rotate enables log file rotation. If false,
	// MaxSizeMb, MaxAgeDays, MaxBackups and Compress values
	// are ignored.
	Rotate bool `yaml:"rotate" json:"rotate"`

	// MaxSize is the maximum size in megabytes of the log file before it gets
	// rotated. It defaults to 100 megabytes.
	MaxSize int `yaml:"maxsize" json:"maxsize"`

	// MaxAge is the maximum number of days to retain old log files based on the
	// timestamp encoded in their filename.  Note that a day is defined as 24
	// hours and may not exactly correspond to calendar days due to daylight
	// savings, leap seconds, etc. The default is not to remove old log files
	// based on age.
	MaxAge int `yaml:"maxage" json:"maxage"`

	// MaxBackups is the maximum number of old log files to retain.  The default
	// is to retain all old log files (though MaxAge may still cause them to get
	// deleted.)
	MaxBackups int `yaml:"maxbackups" json:"maxbackups"`

	// Compress determines if the rotated log files should be compressed
	// using gzip. The default is not to perform compression.
	Compress bool `yaml:"compress" json:"compress"`
}

type validatedFileOutputConfig struct {
	Path            string
	FilePermissions uint32
	DirPermissions  uint32
	Rotate          bool
	MaxSize         int
	MaxAge          int
	MaxBackups      int
	Compress        bool
}

type ConsoleOutputConfig struct {
	Stdout bool `yaml:"stdout" json:"stdout"`

	Prettify bool `yaml:"prettify" json:"prettify"`
}

type validatedConsoleOutputConfig struct {
	Stdout   bool
	Prettify bool
}

type TelegramConfig struct {
	BotToken string `yaml:"bot_token" json:"bot_token"`
	ChatId   string `yaml:"chat_id" json:"chat_id"`

	// LogLevels define the log levels the messages must have to be send to Telegram.
	// If none specified, no messages will be sent to Telegram.
	LogLevels []string `yaml:"from_level" json:"from_level"`

	// WithKeys defines the keys that a log message must contain
	// in order to be sent to Telegram (the value is arbitrary).
	// If a message has at least one of these keys, it will be sent to Telegram.
	// If no keys specified, all messages with specified log level
	// will be sent.
	WithKeys []string `yaml:"with_keys" json:"with_keys"`
}

type validatedTelegramConfig struct {
	BotToken  string
	ChatId    string
	LogLevels []string
	WithKeys  []string
}

// Get returns a pointer to the global zerolog logger (same as zerolog &log.Logger).
func Get() *zerolog.Logger {
	return &log.Logger
}

func ParseYamlConfig(data []byte) (*Config, error) {
	config := &Config{}
	err := yaml.Unmarshal(data, config)
	return config, err
}

func parseTimeFormat(tf string) (string, error) {
	// [none, RFC1123, RFC1123Z, RFC3339, RFC3339Nano, RFC822, RFC822Z, RFC850, RubyDate,
	// Unix, UnixMs, UnixMicro, UnixNano]
	tf = strings.TrimSpace(tf)
	tf = strings.ToUpper(tf)
	switch tf {
	case "NONE", "":
		return "", nil
	case "RFC1123":
		return time.RFC1123, nil
	case "RFC1123Z":
		return time.RFC1123Z, nil
	case "RFC3339":
		return time.RFC3339, nil
	case "RFC3339Nano":
		return time.RFC3339Nano, nil
	case "RFC822":
		return time.RFC822, nil
	case "RFC822Z":
		return time.RFC822Z, nil
	case "RFC850":
		return time.RFC850, nil
	case "RubyDate":
		return time.RubyDate, nil
	case "UNIX":
		return zerolog.TimeFormatUnix, nil
	case "UNIXMS":
		return zerolog.TimeFormatUnixMs, nil
	case "UNIXMICRO":
		return zerolog.TimeFormatUnixMicro, nil
	case "UNIXNANO":
		return zerolog.TimeFormatUnixNano, nil
	}
	return "", ErrBadTimeFormat
}

func validateFileOutputConfig(c *FileOutputConfig) error {
	if c == nil {
		return ErrLogFileOutputConfigIsNil
	}
	if c.Path == "" {
		return ErrLogFileNotSpecified
	}
	if c.DirPermissions > 0777 {
		return ErrBadDirPermissions
	}
	if c.FilePermissions > 0777 {
		return ErrBadFilePermissions
	}

	return nil
}

func validateConsoleOutputConfig(c *ConsoleOutputConfig) error {
	if c == nil {
		return ErrLogConsoleOutputConfigIsNil
	}
	return nil
}

func validateTelegramConfig(c *TelegramConfig) error {
	if c == nil {
		return ErrLogTelegramConfigIsNil
	}
	if c.BotToken == "" {
		return ErrBadTelegramBotToken
	}
	if c.ChatId == "" {
		return ErrBadTelegramChatId
	}
	for _, l := range c.LogLevels {
		l = strings.TrimSpace(l)
		l = strings.ToLower(l)
		_, ok := allowedLogLevels[l]
		if !ok {
			return ErrBadLogLevel
		}
	}
	return nil
}

func validateConfig(c *Config) error {
	c.LogLevel = strings.TrimSpace(c.LogLevel)
	c.LogLevel = strings.ToLower(c.LogLevel)

	_, ok := allowedLogLevels[c.LogLevel]
	if !ok {
		return ErrBadLogLevel
	}

	// Validate time format
	_, err := parseTimeFormat(c.TimeFormat)
	if err != nil {
		return err
	}

	// Validate file output config
	for _, fc := range c.LogFiles {
		err = validateFileOutputConfig(fc)
		if err != nil {
			return err
		}
	}

	// Validate console output config
	for _, cc := range c.Console {
		err = validateConsoleOutputConfig(cc)
		if err != nil {
			return err
		}
	}

	// Validate telegram output config
	for _, tc := range c.Telegram {
		err = validateTelegramConfig(tc)
		if err != nil {
			return err
		}
	}

	return nil
}

func ensureFileExists(path string, filePerm, dirPerm uint32) error {

	// Create path if not exists
	err := os.MkdirAll(filepath.Dir(path), fs.FileMode(dirPerm))
	if err != nil {
		return err
	}

	// O_EXCL Ensure that this call creates the file: if this flag is
	//           specified in conjunction with O_CREAT, and pathname
	//           already exists, then open() fails with the error EEXIST.
	// O_RDONLY, O_WRONLY, or O_RDWR - open file for read, write or read/write
	//           respectively.
	//
	if file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL,
		fs.FileMode(filePerm)); err != nil {
		return err
	} else {
		file.Close()
	}

	return nil
}

// Create creates the app_logger and
// adds it into the default app unit manager (app.M).
// The unit's name is 'app_logger'.
func Create(config *Config) error {

	u := &appLogger{
		unitRunner: app.NewUnitLifecycleRunner(AppLoggerUnitName),
	}

	u.unitRunner.SetOwner(u)

	err := u.init(config)
	if err != nil {
		return err
	}

	err = app.M.AddUnit(u)
	if err != nil {
		return err
	}

	return nil
}

// Start starts the default logger unit.
func Start() error {
	_, _ = app.M.Start(AppLoggerUnitName)
	r := app.M.WaitForCompletion()
	if !r.OK {
		return r.ResultMap[AppLoggerUnitName].CollateralError
	}
	return nil
}

// Pause pauses the default logger unit.
func Pause() error {
	_, _ = app.M.Pause(AppLoggerUnitName)
	r := app.M.WaitForCompletion()
	if !r.OK {
		return r.ResultMap[AppLoggerUnitName].CollateralError
	}
	return nil
}

// Quit quits the default logger unit.
func Quit() error {
	_, _ = app.M.Quit(AppLoggerUnitName)
	r := app.M.WaitForCompletion()
	if !r.OK {
		return r.ResultMap[AppLoggerUnitName].CollateralError
	}
	return nil
}

// appLogger is made private because it is managed by
// the global package functions.
type appLogger struct {
	unitRunner   *app.UnitLifecycleRunner
	availability atomic.Int32
	config       *Config

	// Destinations that are created by Init method
	// and closed by UnitQuit method.
	closableDestinations []io.Closer
}

func (u *appLogger) init(c *Config) error {

	// Validate configuration
	err := validateConfig(c)
	if err != nil {
		return err
	}
	u.config = c

	// Create log output destinations
	var writers []io.Writer

	// Create console writers
	for _, consoleConfig := range u.config.Console {
		dest := os.Stderr
		if consoleConfig.Stdout {
			dest = os.Stdout
		}
		if consoleConfig.Prettify {
			// TODO: manage time format
			writers = append(writers, zerolog.ConsoleWriter{Out: dest,
				TimeFormat: time.RFC3339})

		} else {
			writers = append(writers, dest)
		}
	}

	// Create file writers
	for _, fileConfig := range u.config.LogFiles {

		err := ensureFileExists(fileConfig.Path,
			fileConfig.FilePermissions, fileConfig.DirPermissions)
		if err != nil {
			return fmt.Errorf("(%s) failed to prepare log file %q for writing, reason: %w",
				AppLoggerUnitName, fileConfig.Path, err)
		}

		if fileConfig.Rotate {
			// Create lumberjack.Logger
			logWriterWithRotation := &lumberjack.Logger{
				Filename:   fileConfig.Path,
				MaxBackups: fileConfig.MaxBackups,
				MaxSize:    fileConfig.MaxSize,
				MaxAge:     fileConfig.MaxAge,
				Compress:   fileConfig.Compress,
			}
			u.closableDestinations = append(u.closableDestinations,
				logWriterWithRotation)
			writers = append(writers, logWriterWithRotation)

		} else {
			// Regular file destination
			// O_APPEND - append mode
			// O_CREATE - create if not exists
			// O_WRONLY - write only
			file, err := os.OpenFile(
				fileConfig.Path,
				os.O_APPEND|os.O_CREATE|os.O_WRONLY,
				fs.FileMode(fileConfig.FilePermissions),
			)
			if err != nil {
				return err
			}
			u.closableDestinations = append(u.closableDestinations, file)
			writers = append(writers, file)
		}
	}

	// Create telegram writer
	// for _, tgConfig := range config.Telegram {

	// }

	// time.RFC1123
	// time.RFC1123Z
	// time.RFC3339
	// time.RFC3339Nano
	// time.RFC822
	// time.RFC822Z
	//	time.RFC850
	// time.RubyDate
	// zerolog.TimeFormatUnix
	// zerolog.TimeFormatUnixMs
	// TimeFormatUnixMicro
	// TimeFormatUnixNano

	mw := io.MultiWriter(writers...)

	log.Logger = zerolog.New(mw).With().Timestamp().Logger()

	return nil
}

// UnitStart implements app.IUnit.
func (u *appLogger) UnitStart() app.UnitOperationResult {

	// Start telegram notification service if required
	r := app.UnitOperationResult{
		OK: true,
	}
	return r
}

// UnitPause implements app.IUnit.
func (u *appLogger) UnitPause() app.UnitOperationResult {

	r := app.UnitOperationResult{
		OK: true,
	}
	return r
}

// UnitQuit implements app.IUnit.
func (u *appLogger) UnitQuit() app.UnitOperationResult {
	// Close all destinations that implement io.Closer
	for _, d := range u.closableDestinations {
		_ = d.Close()
	}

	r := app.UnitOperationResult{
		OK: true,
	}
	return r
}

// UnitRunner implements app.IUnit.
func (u *appLogger) UnitRunner() *app.UnitLifecycleRunner {
	return u.unitRunner
}

// UnitAvailability implements app.IUnit.
func (u *appLogger) UnitAvailability() app.UnitAvailability {
	return app.UnitAvailability(u.availability.Load())
}
