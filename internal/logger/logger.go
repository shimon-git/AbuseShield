package logger

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Log struct {
	Level      string `yaml:"log_level"`
	MaxLogSize int    `yaml:"max_log_size"`
	LogFile    string `yaml:"log_file"`
	Enable     bool   `yaml:"log_enable"`
}

func New(l Log) (*zap.Logger, error) {
	var logFile zapcore.WriteSyncer
	var err error
	var logLevel zapcore.Level

	if l.Enable == false {
		return zap.NewNop(), err
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "time"
	encoderCfg.CallerKey = "location"
	encoderCfg.FunctionKey = "function"
	encoderCfg.MessageKey = "message"
	customTimeFormat := "2 Jan 2006 15:04:05"
	encoderCfg.EncodeTime = zapcore.TimeEncoderOfLayout(customTimeFormat)

	encoder := zapcore.NewJSONEncoder(encoderCfg)

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
