package app_logger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"

	"github.com/igulib/app"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/nikoksr/notify"
	"github.com/nikoksr/notify/service/telegram"
)

var (
	DefaultAppLoggerUnitName = "app_logger"

	// DefaultLogTelegramBotTokenEnvVarName specifies the environment variable name
	// to be used as an alternative and safer way to supply the telegram log bot token:
	// LOG_TELEGRAM_BOT_TOKEN.
	DefaultLogTelegramBotTokenEnvVarName = "LOG_TELEGRAM_BOT_TOKEN"
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

// Internal variables

var (
	timestampDisabled = "TS_DISABLED"

	// noVal = struct{}{}

	allowedLogLevels = map[string]zerolog.Level{
		"":         zerolog.DebugLevel,
		"disabled": zerolog.Disabled,
		"trace":    zerolog.TraceLevel,
		"debug":    zerolog.DebugLevel,
		"info":     zerolog.InfoLevel,
		"warning":  zerolog.WarnLevel,
		"error":    zerolog.ErrorLevel,
		"fatal":    zerolog.FatalLevel,
		"panic":    zerolog.PanicLevel,
	}
)

type Config struct {
	// LogLevel must be one of the following:
	// [disabled, trace, debug, info, warning, error, fatal, panic].
	// If not specified, the default log level is "debug".
	LogLevel string `yaml:"log_level" json:"log_level"`

	// TimeFormat must be one of the following:
	// [disabled, RFC1123, RFC1123Z, RFC3339, RFC3339Nano, RFC822, RFC822Z, RFC850, RubyDate,
	// Unix, UnixMs, UnixMicro, UnixNano].
	// See golang time package documentation for more info about date/time formats.
	// If not specified, the default time format is RFC3339.
	TimeFormat string `yaml:"time_format" json:"time_format"`

	// UseUTC allows to use UTC time instead of local time.
	// This doesn't have effect if one of the unix timestamp formats is selected as TimeFormat
	// or if TimeFormat is "disabled".
	// The local time is used by default.
	UseUTC bool `yaml:"use_utc" json:"use_utc"`

	LogFiles []*FileOutputConfig    `yaml:"log_files" json:"log_files"`
	Console  []*ConsoleOutputConfig `yaml:"console" json:"console"`
	Telegram *TelegramConfig        `yaml:"telegram" json:"telegram"`
}

type validatedConfig struct {
	LogLevel             zerolog.Level
	TimeFormat           string
	PrettifiedTimeFormat string
	UseUTC               bool
	LogFiles             []*validatedFileOutputConfig
	Console              []*validatedConsoleOutputConfig
	Telegram             *validatedTelegramConfig
}

type FileOutputConfig struct {
	// Path is the complete path to the log file,
	// either absolute or relative.
	Path string `yaml:"path" json:"path"`

	// FilePermissions defines the permissions to be applied to the log file,
	// e.g. 0660.
	// If zero, no permissions will be applied.
	FilePermissions uint32 `yaml:"file_permissions" json:"file_permissions"`

	FileOwner string `yaml:"file_owner" json:"file_owner"`

	// FilePermissions defines the permissions to be applied to the directory
	// containing the log file.
	// If zero, no permissions will be applied.
	DirPermissions uint32 `yaml:"dir_permissions" json:"dir_permissions"`

	DirOwner string `yaml:"dir_owner" json:"dir_owner"`

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
	UseStdout bool `yaml:"use_stdout" json:"use_stdout"`

	Prettify bool `yaml:"prettify" json:"prettify"`
}

type validatedConsoleOutputConfig struct {
	Stdout   bool
	Prettify bool
}

type TelegramConfig struct {
	BotToken string  `yaml:"bot_token" json:"bot_token"`
	ChatIds  []int64 `yaml:"chat_ids" json:"chat_ids"`

	// LogLevels define the log levels the messages must have to be send to Telegram.
	// If none specified, no messages will be sent to Telegram.
	LogLevels []string `yaml:"log_levels" json:"log_levels"`

	// WithKeys defines the keys that a log message must contain
	// in order to be sent to Telegram (the value is arbitrary).
	// If a message has at least one of these keys, it will be sent to Telegram.
	// If no keys specified, all messages with specified log level
	// will be sent.
	WithKeys []string `yaml:"with_keys" json:"with_keys"`
}

type validatedTelegramConfig struct {
	BotToken  string
	ChatIds   []int64
	LogLevels []zerolog.Level
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

func validateTimeFormat(tf string) (string, string, error) {
	// [disabled, RFC1123, RFC1123Z, RFC3339, RFC3339Nano, RFC822, RFC822Z, RFC850, RubyDate,
	// Unix, UnixMs, UnixMicro, UnixNano]
	tf = strings.TrimSpace(tf)
	tf = strings.ToUpper(tf)
	prettified := "15:04:05 -07"
	switch tf {
	case "DISABLED":
		return timestampDisabled, prettified, nil
	case "": // default is time.RFC3339
		return time.RFC3339, prettified, nil
	case "RFC1123":
		return time.RFC1123, prettified, nil
	case "RFC1123Z":
		return time.RFC1123Z, prettified, nil
	case "RFC3339":
		return time.RFC3339, prettified, nil
	case "RFC3339NANO":
		return time.RFC3339Nano, "15:04:05.000000000 -07", nil
	case "RFC822":
		return time.RFC822, prettified, nil
	case "RFC822Z":
		return time.RFC822Z, prettified, nil
	case "RFC850":
		return time.RFC850, prettified, nil
	case "RUBYDATE":
		return time.RubyDate, prettified, nil
	case "UNIX":
		return zerolog.TimeFormatUnix, prettified, nil
	case "UNIXMS":
		return zerolog.TimeFormatUnixMs, "15:04:05.000 -07", nil
	case "UNIXMICRO":
		return zerolog.TimeFormatUnixMicro, "15:04:05.000000 -07", nil
	case "UNIXNANO":
		return zerolog.TimeFormatUnixNano, "15:04:05.000000000 -07", nil
	}
	return "", "", ErrBadTimeFormat
}

func validateFileOutputConfig(c *FileOutputConfig) (*validatedFileOutputConfig, error) {
	v := &validatedFileOutputConfig{}
	if c == nil {
		return v, ErrLogFileOutputConfigIsNil
	}
	if c.Path == "" {
		return v, ErrLogFileNotSpecified
	}
	v.Path = c.Path

	if c.DirPermissions > 0777 {
		return v, ErrBadDirPermissions
	}
	v.DirPermissions = c.DirPermissions

	if c.FilePermissions > 0777 {
		return v, ErrBadFilePermissions
	}
	v.FilePermissions = c.FilePermissions

	if c.MaxAge < 0 {
		return v, errors.New("MaxAge of rotated log file can't be negative, it specifies duration in days")
	}
	v.MaxAge = c.MaxAge

	if c.MaxBackups < 0 {
		return v, errors.New("MaxBackups of rotated log file can't be negative, it specifies the number of old logs to retain")
	}
	v.MaxBackups = c.MaxBackups

	if c.MaxSize < 0 {
		return v, errors.New("MaxSize of rotated log file can't be negative")
	}
	v.MaxSize = c.MaxSize

	// Fields that do not require validation
	v.Compress = c.Compress
	v.Rotate = c.Rotate

	return v, nil
}

func validateConsoleOutputConfig(c *ConsoleOutputConfig) (*validatedConsoleOutputConfig, error) {
	v := &validatedConsoleOutputConfig{}
	if c == nil {
		return v, ErrLogConsoleOutputConfigIsNil
	}

	// Fields that do not require validation
	v.Prettify = c.Prettify
	v.Stdout = c.UseStdout

	return v, nil
}

func validateTelegramConfig(c *TelegramConfig) (*validatedTelegramConfig, error) {
	v := &validatedTelegramConfig{
		ChatIds:   make([]int64, 0),
		LogLevels: make([]zerolog.Level, 0),
		WithKeys:  make([]string, 0),
	}
	if c == nil {
		return v, ErrLogTelegramConfigIsNil
	}

	// Env var value has precedence
	botToken := os.Getenv(DefaultLogTelegramBotTokenEnvVarName)
	if botToken == "" {
		if c.BotToken == "" {
			return v, ErrBadTelegramBotToken
		}
		v.BotToken = c.BotToken
	} else {
		v.BotToken = botToken
	}

	if len(c.ChatIds) == 0 {
		return v, ErrBadTelegramChatId
	}
	v.ChatIds = append(v.ChatIds, c.ChatIds...)

	for _, l := range c.LogLevels {
		l = strings.TrimSpace(l)
		l = strings.ToLower(l)
		parsedLevel, ok := allowedLogLevels[l]
		if !ok {
			return v, ErrBadLogLevel
		}
		v.LogLevels = append(v.LogLevels, parsedLevel)
	}

	v.WithKeys = append(v.WithKeys, c.WithKeys...)

	// Fields that do not require validation
	// none

	return v, nil
}

func validateConfig(c *Config) (*validatedConfig, error) {
	v := &validatedConfig{
		LogFiles: make([]*validatedFileOutputConfig, 0),
		Console:  make([]*validatedConsoleOutputConfig, 0),
		// Telegram: make([]*validatedTelegramConfig, 0),
	}
	logLevel := strings.TrimSpace(c.LogLevel)
	logLevel = strings.ToLower(logLevel)

	parsedLevel, ok := allowedLogLevels[logLevel]
	if !ok {
		return v, ErrBadLogLevel
	}

	v.LogLevel = parsedLevel

	// Validate time format
	timeFormat, prettifiedTimeFormat, err := validateTimeFormat(c.TimeFormat)
	if err != nil {
		return v, err
	}
	v.TimeFormat = timeFormat
	v.PrettifiedTimeFormat = prettifiedTimeFormat

	// Validate file output config
	for _, fc := range c.LogFiles {
		valFileConfig, err := validateFileOutputConfig(fc)
		v.LogFiles = append(v.LogFiles, valFileConfig)
		if err != nil {
			return v, err
		}
	}

	// Validate console output config
	for _, cc := range c.Console {
		valConsoleConfig, err := validateConsoleOutputConfig(cc)
		v.Console = append(v.Console, valConsoleConfig)
		if err != nil {
			return v, err
		}
	}

	// Validate telegram output config
	if c.Telegram != nil {
		valTgConfig, err := validateTelegramConfig(c.Telegram)
		v.Telegram = valTgConfig
		if err != nil {
			return v, err
		}
	}

	// Fields that do not require validation
	v.UseUTC = c.UseUTC

	return v, nil
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
		unitRunner: app.NewUnitLifecycleRunner(DefaultAppLoggerUnitName),
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
	_, _ = app.M.Start(DefaultAppLoggerUnitName)
	r := app.M.WaitForCompletion()
	if !r.OK {
		return r.ResultMap[DefaultAppLoggerUnitName].CollateralError
	}
	return nil
}

// Pause pauses the default logger unit.
func Pause() error {
	_, _ = app.M.Pause(DefaultAppLoggerUnitName)
	r := app.M.WaitForCompletion()
	if !r.OK {
		return r.ResultMap[DefaultAppLoggerUnitName].CollateralError
	}
	return nil
}

// Quit quits the default logger unit.
func Quit() error {
	_, _ = app.M.Quit(DefaultAppLoggerUnitName)
	r := app.M.WaitForCompletion()
	if !r.OK {
		return r.ResultMap[DefaultAppLoggerUnitName].CollateralError
	}
	return nil
}

// appLogger is made private because it is managed by
// the global package functions.
type appLogger struct {
	unitRunner   *app.UnitLifecycleRunner
	availability atomic.Int32
	config       *validatedConfig

	// Destinations that are created by Init method
	// and closed by UnitQuit method.
	closableDestinations []io.Closer

	// Telegram service
	tgServiceRunning atomic.Bool

	// tgServiceCtx     context.Context
	tgMsgChan         chan string
	tgQuitRequestChan chan struct{}
	tgServiceDone     chan struct{}
	tgRequestCounter  sync.WaitGroup
}

func createPrettifiedConsoleFormatter(vc *validatedConfig) func(i interface{}) string {
	return func(i interface{}) string {
		t := ""
		switch tt := i.(type) {
		case string:
			ts, err := time.ParseInLocation(zerolog.TimeFieldFormat, tt, time.Local)
			if err != nil {
				t = tt
			} else {
				if vc.UseUTC {
					t = ts.UTC().Format(vc.PrettifiedTimeFormat)
				} else {
					t = ts.Local().Format(vc.PrettifiedTimeFormat)
				}
			}
		case json.Number:
			i, err := tt.Int64()
			if err != nil {
				t = tt.String()
			} else {
				var sec, nsec int64

				switch zerolog.TimeFieldFormat {
				case zerolog.TimeFormatUnixNano:
					sec, nsec = 0, i
				case zerolog.TimeFormatUnixMicro:
					sec, nsec = 0, int64(time.Duration(i)*time.Microsecond)
				case zerolog.TimeFormatUnixMs:
					sec, nsec = 0, int64(time.Duration(i)*time.Millisecond)
				default:
					sec, nsec = i, 0
				}

				ts := time.Unix(sec, nsec)
				if vc.UseUTC {
					t = ts.UTC().Format(vc.PrettifiedTimeFormat)
				} else {
					t = ts.Format(vc.PrettifiedTimeFormat)
				}
			}
		}
		return t
	}

}

func (u *appLogger) init(c *Config) error {

	// Validate configuration
	vc, err := validateConfig(c)
	if err != nil {
		return err
	}
	u.config = vc

	// Set global level
	zerolog.SetGlobalLevel(vc.LogLevel)

	// Create log output destinations
	var writers []io.Writer

	// Set default time format
	if vc.TimeFormat != timestampDisabled {
		zerolog.TimeFieldFormat = vc.TimeFormat
	}

	// Create console writers
	for _, consoleConfig := range u.config.Console {
		dest := os.Stderr
		if consoleConfig.Stdout {
			dest = os.Stdout
		}
		if consoleConfig.Prettify {
			cw := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
				w.Out = dest
				w.TimeFormat = vc.PrettifiedTimeFormat
				w.FormatTimestamp = createPrettifiedConsoleFormatter(vc)
			})
			writers = append(writers, cw)

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
				DefaultAppLoggerUnitName, fileConfig.Path, err)
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

	// Create telegram writers

	// for _, tgConfig := range vc.Telegram {

	// }

	if vc.UseUTC {
		zerolog.TimestampFunc = func() time.Time {
			return time.Now().UTC()
		}
	}

	mw := io.MultiWriter(writers...)

	if vc.TimeFormat == timestampDisabled {
		log.Logger = zerolog.New(mw).With().Logger()
	} else {
		log.Logger = zerolog.New(mw).With().Timestamp().Logger()
	}

	// Add telegram hook if telegram output defined
	if vc.Telegram != nil {
		log.Logger = log.Logger.Hook(u)
		u.tgMsgChan = make(chan string, 50) // TODO: replace magic number
	}

	return nil
}

// UnitStart implements zerolog.Hook.
func (u *appLogger) Run(
	e *zerolog.Event,
	level zerolog.Level,
	message string,
) {
	// Check if message has required log level
	levelOk := false
	for _, allowedLevel := range u.config.Telegram.LogLevels {
		if level == allowedLevel {
			levelOk = true
			break
		}
	}

	if levelOk {
		// wg.Add(1)
		// go func() {
		// 	_ = notifyTelegram("", message)
		// 	wg.Done()
		// }()
		u.tgMsgChan <- message
	}
}

// UnitStart implements app.IUnit.
func (u *appLogger) UnitStart() app.UnitOperationResult {

	// Start telegram notification service if configured
	if u.config.Telegram != nil {
		swapped := u.tgServiceRunning.CompareAndSwap(false, true)
		if swapped {
			u.tgQuitRequestChan = make(chan struct{})
			u.tgServiceDone = make(chan struct{})
			go u.telegramService()
		}
	}

	u.availability.Store(int32(app.UAvailable))

	r := app.UnitOperationResult{
		OK: true,
	}
	return r
}

// UnitPause implements app.IUnit.
func (u *appLogger) UnitPause() app.UnitOperationResult {

	u.availability.Store(int32(app.UTemporarilyUnavailable))

	r := app.UnitOperationResult{
		OK: true,
	}
	return r
}

// UnitQuit implements app.IUnit.
func (u *appLogger) UnitQuit() app.UnitOperationResult {
	u.availability.Store(int32(app.UNotAvailable))

	// Shut down telegram service if running
	swapped := u.tgServiceRunning.CompareAndSwap(true, false)
	if swapped {
		// Wait until all telegram requests are complete.
		// u.tgRequestCounter.Wait()
		close(u.tgQuitRequestChan)
		// Wait until telegram service goroutine exits
		<-u.tgServiceDone
	}

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

// This method should only be called from UnitStart method with proper synchronization.
func (u *appLogger) telegramService() {
	defer close(u.tgServiceDone)

	telegramService, err := telegram.New(
		u.config.Telegram.BotToken,
	)

	if err != nil {
		u.availability.Store(int32(app.UNotAvailable))
		return
	}

	telegramService.AddReceivers(u.config.Telegram.ChatIds...)

	notifier := notify.New()

	notifier.UseServices(telegramService)

	for {
		select {
		case msg := <-u.tgMsgChan:
			// Process each request in a separate goroutine
			u.tgRequestCounter.Add(1)
			go func() { // This goroutine must not produce timeouts!
				defer u.tgRequestCounter.Done()
				// if msg.ResponseDelayMillis > 0 {
				// 	time.Sleep(time.Duration(msg.ResponseDelayMillis) * time.Millisecond)
				// }
				// Simply echo the message back.
				// We could also check app.IsShuttingDown()
				// to determine a better processing strategy
				// if required.
				// msg.ResponseChan <- test_unit.ApiResponse{
				// 	Error: nil,
				// 	Msg:   msg.Payload,
				// }

				// fmt.Printf("Simulating telegram msg processing: %q\n", msg)

				ctx, cancel := context.WithTimeout(
					context.Background(),
					5*time.Second, // TODO: remove magic numbers
				)

				defer cancel()

				err = notifier.Send(ctx, "Log Message", msg)
				if err != nil {
					logger := Get()
					logger.Error().Err(err).Msg("failed to send message to telegram")
				}
			}()

		case <-u.tgQuitRequestChan:
			u.tgRequestCounter.Wait()
			return
		}
	}
}
