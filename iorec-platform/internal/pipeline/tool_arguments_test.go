package pipeline

import "testing"

func TestChatToolArgumentsRemainAvailableForProgress(t *testing.T) {
	request := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"tool1","function":{"name":"terminal","arguments":"{\"command\":\"echo yes\"}"}}]},{"role":"tool","tool_call_id":"tool1","content":"yes"}]}`)
	n, err := NormalizeRequest("chat_completions", request)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"command":"echo yes"}`
	if len(n.Messages) != 2 || n.Messages[0].ToolCalls[0].Arguments != want || n.Messages[1].ToolCallID != "tool1" {
		t.Fatal("request lost tool operation/result identity")
	}
	ApplyStream(n, []string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"tool2","function":{"name":"terminal","arguments":"{\"command\":"}}]}}]}` + "\n\n",
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"echo yes\"}"}}]},"finish_reason":"tool_calls"}]}` + "\n\n",
		"data: [DONE]\n\n",
	})
	if len(n.ResponseToolCalls) != 1 || n.ResponseToolCalls[0].Arguments != want || n.ResponseToolCalls[0].ArgsHash != argsHash(want) {
		t.Fatalf("stream lost joined arguments: %+v", n.ResponseToolCalls)
	}
	for _, response := range []string{
		`{"choices":[{"message":{"tool_calls":[{"id":"t","function":{"name":"terminal","arguments":"{\"command\":\"echo yes\"}"}}]}}]}`,
		`{"assistant_message":{"tool_calls":[{"id":"t","function":{"name":"terminal","arguments":"{\"command\":\"echo yes\"}"}}]}}`,
	} {
		n := &Normalized{APIMode: "chat_completions"}
		ApplyResponseBody(n, []byte(response))
		if len(n.ResponseToolCalls) != 1 || n.ResponseToolCalls[0].Arguments != want {
			t.Fatal("body/native response lost tool arguments")
		}
	}
}
