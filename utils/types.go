package utils

type AuthRequest struct {
	Token string
	Port  uint16
}

func (r AuthRequest) IsValid() bool {
	return r.Token != "" && r.Port != 0
}
