package logger

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Log struct {
	Level         string `yaml:"log_level"`
	MaxLogSize    int    `yaml:"max_log_size"`
	LogFile       string `yaml:"log_file"`
	Enable        bool   `yaml:"log_enable"`
	JsonLogFormat bool   `yaml:"json_log_format"`
}

func New(l Log) (*zap.Logger, error) {
	var logFile zapcore.WriteSyncer
	var err error
	var logLevel zapcore.Level

	if l.Enable == false {
		return zap.NewNop(), err
	}
	var encoder zapcore.Encoder
	if l.JsonLogFormat {
		// Default to JSON encoder if not specified or specified format is not recognized
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.TimeKey = "time"
		encoderConfig.CallerKey = "location"
		encoderConfig.FunctionKey = "function"
		encoderConfig.MessageKey = "message"
		customTimeFormat := "2 Jan 2006 15:04:05"
		encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(customTimeFormat)
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoderConfig := zap.NewDevelopmentEncoderConfig()
		customTimeFormat := "2 Jan 2006 15:04:05"
		encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(customTimeFormat)
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	if l.MaxLogSize > 0 {
		logFile = zapcore.AddSync(&lumberjack.Logger{
			Filename:  l.LogFile,
			MaxSize:   l.MaxLogSize,
			LocalTime: true,
		})
	} else {
		logFile, err = os.OpenFile(l.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return &zap.Logger{}, err
		}
	}

	switch strings.ToLower(l.Level) {
	case "debug":
		logLevel = zap.DebugLevel
	case "info":
		logLevel = zap.InfoLevel
	case "error":
		logLevel = zap.ErrorLevel
	}

	core := zapcore.NewCore(encoder, logFile, zap.NewAtomicLevelAt(logLevel))

	logger := zap.New(core, zap.AddCaller(), zap.Fields(zap.Int("pid", os.Getpid())))
	return logger, nil
}

func NewDummyLogger() *zap.Logger {
	return zap.NewNop()
}
