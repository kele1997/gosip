package core

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ghettovoice/gosip/log"
)

// Response RFC 3261 - 7.2.
type Response interface {
	Message
	StatusCode() StatusCode
	SetStatusCode(code StatusCode)
	Reason() string
	SetReason(reason string)
	/* Common helpers */
	IsProvisional() bool
	IsSuccess() bool
	IsRedirection() bool
	IsClientError() bool
	IsServerError() bool
	IsGlobalError() bool
}

type response struct {
	message
	status StatusCode
	reason string
}

func NewResponse(
	sipVersion string,
	statusCode StatusCode,
	reason string,
	hdrs []Header,
	body string,
	logger log.Logger,
) Response {
	res := new(response)
	res.SetSipVersion(sipVersion)
	res.headers = newHeaders(hdrs)
	res.SetStatusCode(statusCode)
	res.SetReason(reason)
	res.SetLog(logger)

	if strings.TrimSpace(body) != "" {
		res.SetBody(body)
	}

	return res
}

func (res *response) StatusCode() StatusCode {
	return res.status
}
func (res *response) SetStatusCode(code StatusCode) {
	res.status = code
}

func (res *response) Reason() string {
	return res.reason
}
func (res *response) SetReason(reason string) {
	res.reason = reason
}

// StartLine returns Response Status Line - RFC 2361 7.2.
func (res *response) StartLine() string {
	var buffer bytes.Buffer

	// Every SIP response starts with a Status Line - RFC 2361 7.2.
	buffer.WriteString(
		fmt.Sprintf(
			"%s %d %s",
			res.SipVersion(),
			res.StatusCode(),
			res.Reason(),
		),
	)

	return buffer.String()
}

func (res *response) Short() string {
	var buffer bytes.Buffer

	buffer.WriteString(res.StartLine())

	if cseq, ok := res.CSeq(); ok {
		buffer.WriteString(fmt.Sprintf(" (%s)", cseq))
	}

	return buffer.String()
}

func (res *response) String() string {
	var buffer bytes.Buffer

	// write message start line
	buffer.WriteString(res.StartLine() + "\r\n")
	// Write the headers.
	buffer.WriteString(res.headers.String())
	// If the request has a message body, add it.
	buffer.WriteString("\r\n" + res.Body())

	return buffer.String()
}

func (res *response) Clone() Message {
	return NewResponse(
		res.SipVersion(),
		res.StatusCode(),
		res.Reason(),
		res.headers.CloneHeaders(),
		res.Body(),
		res.Log(),
	)
}

func (res *response) IsProvisional() bool {
	return res.StatusCode() < 200
}

func (res *response) IsSuccess() bool {
	return res.StatusCode() >= 200 && res.StatusCode() < 300
}

func (res *response) IsRedirection() bool {
	return res.StatusCode() >= 300 && res.StatusCode() < 400
}

func (res *response) IsClientError() bool {
	return res.StatusCode() >= 400 && res.StatusCode() < 500
}

func (res *response) IsServerError() bool {
	return res.StatusCode() >= 500 && res.StatusCode() < 600
}

func (res *response) IsGlobalError() bool {
	return res.StatusCode() >= 600
}