package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

// Verify the JSON response shape observed by this test; this does not establish parity with another binary.
//
//	JsonOkResult: {"code":0,"message":"ok","type":"success","result":<data>}
//	JsonOkMessage:{"code":0,"message":"ok","type":<msg>}
//	JsonErr:     {"code":-1,"message":<msg>,"type":"error","result":null}
//	JsonTimeout: {"code":-1,"result":null}
func newTestController() (*ApiBaseController, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := &ApiBaseController{}
	c.Controller.Ctx = context.NewContext()
	c.Controller.Data = make(map[interface{}]interface{})
	c.Controller.Ctx.Reset(rec, req)
	return c, rec
}

func serveJSON(rec *httptest.ResponseRecorder, t *testing.T) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("non-JSON response %q: %v", rec.Body.String(), err)
	}
	return body
}

func TestJsonOkResultFormat(t *testing.T) {
	c, rec := newTestController()
	c.JsonOkResult(map[string]interface{}{"total": 3, "items": []int{1, 2, 3}})
	body := serveJSON(rec, t)
	if body["code"] != float64(0) {
		t.Errorf("code = %#v, want 0", body["code"])
	}
	if body["message"] != "ok" {
		t.Errorf("message = %#v, want ok", body["message"])
	}
	if body["type"] != "success" {
		t.Errorf("type = %#v, want success", body["type"])
	}
	result, ok := body["result"].(map[string]interface{})
	if !ok || result["total"] != float64(3) {
		t.Errorf("result = %#v, want {total:3,...}", body["result"])
	}
}

func TestJsonOkMessageFormat(t *testing.T) {
	c, rec := newTestController()
	c.JsonOkMessage("ok")
	body := serveJSON(rec, t)
	if body["code"] != float64(0) || body["type"] != "ok" || body["message"] != "ok" {
		t.Errorf("JsonOkMessage = %#v", body)
	}
	if _, hasResult := body["result"]; hasResult {
		t.Errorf("JsonOkMessage should not include result key: %#v", body)
	}
}

func TestJsonErrFormat(t *testing.T) {
	c, rec := newTestController()
	c.JsonErr("id error")
	body := serveJSON(rec, t)
	if body["code"] != float64(-1) {
		t.Errorf("code = %#v, want -1", body["code"])
	}
	if body["message"] != "id error" {
		t.Errorf("message = %#v, want id error", body["message"])
	}
	if body["type"] != "error" {
		t.Errorf("type = %#v, want error", body["type"])
	}
	if body["result"] != nil {
		t.Errorf("result = %#v, want nil", body["result"])
	}
}

func TestJsonTimeoutFormat(t *testing.T) {
	c, rec := newTestController()
	c.JsonTimeout()
	body := serveJSON(rec, t)
	if body["code"] != float64(-1) {
		t.Errorf("code = %#v, want -1", body["code"])
	}
	if body["result"] != nil {
		t.Errorf("result = %#v, want nil", body["result"])
	}
	if _, hasType := body["type"]; hasType {
		t.Errorf("JsonTimeout should not include type key: %#v", body)
	}
}
