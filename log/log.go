package log

type Logger interface {
	Debug(args ...any)
	Debugf(format string, args ...any)
	Info(args ...any)
	Infof(format string, args ...any)
	Warn(args ...any)
	Warnf(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
}

type NopLogger struct{}

func (n NopLogger) Debug(args ...any)                 {}
func (n NopLogger) Debugf(format string, args ...any) {}
func (n NopLogger) Info(args ...any)                  {}
func (n NopLogger) Infof(format string, args ...any)  {}
func (n NopLogger) Warn(args ...any)                  {}
func (n NopLogger) Warnf(format string, args ...any)  {}
func (n NopLogger) Error(args ...any)                 {}
func (n NopLogger) Errorf(format string, args ...any) {}
