package api

type Api struct {
	Id   string
	Path string
}

type Apier interface {
	Connect(string) error
	Authenticate(string, string) error
	SendPublic(string, string, string) error
	GetPublic(string, string) (string, error)
	SendPrivate(string, string, string) error
	GetPrivate(string, string) (string, error)
	DeletePrivate(string, string) error
	Push(string, string, string, string) error
	PushIncoming(string, string, string) error
	PushOutgoing(string, string, string) error
	Pop(string, string, string) (string, error)
	PopIncoming(string, string) (string, error)
	PopOutgoing(string, string) (string, error)
	Size(string, string, string) (int, error)
	OutgoingSize(string, string) (int, error)
	IncomingSize(string, string) (int, error)
}
