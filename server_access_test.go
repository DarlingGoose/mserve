package mserve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DarlingGoose/credentials/session"
	"github.com/DarlingGoose/rbac"
	"github.com/gorilla/mux"
)

func TestHTTPMethodToAction(t *testing.T) {
	tests := map[string]rbac.Action{
		http.MethodGet:    rbac.ActionRead,
		http.MethodHead:   rbac.ActionRead,
		http.MethodPost:   rbac.ActionCreate,
		http.MethodPut:    rbac.ActionUpdate,
		http.MethodPatch:  rbac.ActionUpdate,
		http.MethodDelete: rbac.ActionDelete,
		http.MethodTrace:  "",
	}
	for method, want := range tests {
		t.Run(method, func(t *testing.T) {
			if got := httpMethodToAction(method); got != want {
				t.Fatalf("httpMethodToAction(%q) = %q, want %q", method, got, want)
			}
		})
	}
}

func TestEndpointAccessPolicyValidation(t *testing.T) {
	tests := []struct {
		name     string
		endpoint Endpoint
		wantErr  bool
	}{
		{name: "missing policy fails closed", endpoint: Endpoint{Path: "/lessons"}, wantErr: true},
		{name: "explicit public", endpoint: Endpoint{Path: "/lessons", Access: AccessPolicy{Public: true}}},
		{name: "authenticated", endpoint: Endpoint{Path: "/lessons", Access: AccessPolicy{Authenticated: true}}},
		{name: "legacy roles remain protected", endpoint: Endpoint{Path: "/lessons", Roles: []Role{{Role: "teacher"}}}},
		{name: "public and authenticated conflict", endpoint: Endpoint{Path: "/lessons", Access: AccessPolicy{Public: true, Authenticated: true}}, wantErr: true},
		{name: "public RBAC conflict", endpoint: Endpoint{Path: "/lessons", Access: AccessPolicy{Public: true, ResourceType: "lesson"}}, wantErr: true},
		{name: "public roles conflict", endpoint: Endpoint{Path: "/lessons", Access: AccessPolicy{Public: true}, Roles: []Role{{Role: "teacher"}}}, wantErr: true},
		{name: "parameter needs type", endpoint: Endpoint{Path: "/lessons/{id}", Access: AccessPolicy{Authenticated: true, ResourceParam: "id"}}, wantErr: true},
		{name: "parameter must exist in route", endpoint: Endpoint{Path: "/lessons/{id}", Access: AccessPolicy{Authenticated: true, ResourceType: "lesson", ResourceParam: "lesson_id"}}, wantErr: true},
		{name: "scoped policy", endpoint: Endpoint{Path: "/lessons/{id}", Access: AccessPolicy{Authenticated: true, ResourceType: "lesson", ResourceParam: "id", Action: rbac.ActionUpdate}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.endpoint.validateAccessPolicy()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAccessPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddEndpointsRequiresExplicitAccess(t *testing.T) {
	server := NewServer("learning", nil, nil, nil, SSLConfig{})
	handler := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

	err := server.AddEndpoints(context.Background(), &Endpoint{
		Path:    "/implicit",
		Methods: []string{http.MethodGet},
		Handler: handler,
	})
	if err == nil {
		t.Fatal("AddEndpoints() accepted an endpoint without an access policy")
	}

	err = server.AddEndpoints(context.Background(), &Endpoint{
		Path:    "/public",
		Methods: []string{http.MethodGet},
		Handler: handler,
		Access:  AccessPolicy{Public: true},
	})
	if err != nil {
		t.Fatalf("AddEndpoints() public endpoint error = %v", err)
	}

	recorder := httptest.NewRecorder()
	server.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/public", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("public endpoint status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestAuthenticatedEndpointRejectsAnonymousRequests(t *testing.T) {
	secret := []byte("test-secret")
	sessionClient := session.NewClient(nil, nil, secret, time.Hour)
	server := NewServer("learning", nil, nil, sessionClient, SSLConfig{})
	err := server.AddEndpoints(context.Background(), &Endpoint{
		Path:    "/workspace",
		Methods: []string{http.MethodGet},
		Handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
		Access:  AccessPolicy{Authenticated: true},
	})
	if err != nil {
		t.Fatalf("AddEndpoints() error = %v", err)
	}

	anonymous := httptest.NewRecorder()
	server.router.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/workspace", nil))
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want %d", anonymous.Code, http.StatusUnauthorized)
	}

	cookieRecorder := httptest.NewRecorder()
	err = session.SetSessionCookie(cookieRecorder, &session.UserSessionData{
		UserID:    "student-1",
		SignedIn:  true,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, secret)
	if err != nil {
		t.Fatalf("SetSessionCookie() error = %v", err)
	}
	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/workspace", nil)
	authenticatedRequest.AddCookie(cookieRecorder.Result().Cookies()[0])
	authenticated := httptest.NewRecorder()
	server.router.ServeHTTP(authenticated, authenticatedRequest)
	if authenticated.Code != http.StatusNoContent {
		t.Fatalf("authenticated status = %d, want %d", authenticated.Code, http.StatusNoContent)
	}
}

func TestScopedResourceUsesConcreteRouteValue(t *testing.T) {
	server := NewServer("learning", nil, nil, nil, SSLConfig{})
	endpoint := &Endpoint{Access: AccessPolicy{ResourceType: "lesson", ResourceParam: "lesson_id"}}
	request := mux.SetURLVars(httptest.NewRequest(http.MethodPatch, "/lessons/unit/1", nil), map[string]string{
		"lesson_id": "unit/1",
	})

	got, err := server.endpointResource(endpoint, request)
	if err != nil {
		t.Fatalf("endpointResource() error = %v", err)
	}
	if want := "learning.lesson.unit%2F1"; got != want {
		t.Fatalf("endpointResource() = %q, want %q", got, want)
	}
}

func TestEmptyCORSAllowlistDoesNotReflectOrigin(t *testing.T) {
	server := NewServer("learning", nil, nil, nil, SSLConfig{})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Origin", "https://attacker.example")

	if got, err := server.matchOrigin(request); err == nil || got != "" {
		t.Fatalf("matchOrigin() = %q, %v; want empty origin and an error", got, err)
	}

	server.AddOrigin("https://app.example")
	request.Header.Set("Origin", "https://app.example")
	if got, err := server.matchOrigin(request); err != nil || got != "https://app.example" {
		t.Fatalf("matchOrigin() = %q, %v; want configured origin", got, err)
	}
}
