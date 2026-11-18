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

type resourceResolverFunc func(context.Context, rbac.ResourceRef) (*rbac.ResourceRef, error)

func (f resourceResolverFunc) Parent(ctx context.Context, resource rbac.ResourceRef) (*rbac.ResourceRef, error) {
	return f(ctx, resource)
}

func TestRBACHTTPMethodToAction(t *testing.T) {
	tests := map[string]rbac.Action{
		http.MethodGet:    rbac.ActionRead,
		http.MethodHead:   rbac.ActionRead,
		http.MethodPost:   rbac.ActionCreate,
		http.MethodPut:    rbac.ActionUpdate,
		http.MethodPatch:  rbac.ActionUpdate,
		http.MethodDelete: rbac.ActionDelete,
		http.MethodTrace:  rbac.ActionUnknown,
	}
	for method, want := range tests {
		t.Run(method, func(t *testing.T) {
			if got := rbac.HTTPMethodToAction(method); got != want {
				t.Fatalf("rbac.HTTPMethodToAction(%q) = %q, want %q", method, got, want)
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

func TestAuthenticatedEndpointAcceptsRotatingSessionKeys(t *testing.T) {
	rootSecret := []byte("0123456789abcdef0123456789abcdef")
	keys, err := session.NewRotatingKeyRing(rootSecret, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewRotatingKeyRing() error = %v", err)
	}
	sessionClient, err := session.NewClientWithKeyRing(nil, nil, keys, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewClientWithKeyRing() error = %v", err)
	}
	server := NewServer("learning", nil, nil, sessionClient, SSLConfig{})
	err = server.AddEndpoints(context.Background(), &Endpoint{
		Path:    "/workspace",
		Methods: []string{http.MethodGet},
		Handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
		Access:  AccessPolicy{Authenticated: true},
	})
	if err != nil {
		t.Fatalf("AddEndpoints() error = %v", err)
	}

	cookieRecorder := httptest.NewRecorder()
	err = session.SetSessionCookieWithKeyRing(cookieRecorder, &session.UserSessionData{
		UserID:    "teacher-1",
		SignedIn:  true,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, keys)
	if err != nil {
		t.Fatalf("SetSessionCookieWithKeyRing() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/workspace", nil)
	request.AddCookie(cookieRecorder.Result().Cookies()[0])
	recorder := httptest.NewRecorder()
	server.router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("rotating-key session status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestScopedEndpointUsesRBACRoleAssignments(t *testing.T) {
	ctx := context.Background()
	repository := rbac.NewMockRepo()
	manager := rbac.NewMockRepoManager(repository)
	permission := &rbac.Permission{ID: "update-lesson", Resource: "lesson", Action: rbac.ActionUpdate}
	role := &rbac.Role{ID: "teacher", Name: "teacher"}
	if err := manager.CreatePermission(ctx, permission); err != nil {
		t.Fatalf("CreatePermission() error = %v", err)
	}
	if err := manager.CreateRole(ctx, role); err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	if err := manager.AssignPermissionToRole(ctx, role.ID, permission.ID); err != nil {
		t.Fatalf("AssignPermissionToRole() error = %v", err)
	}
	if err := manager.AssignRole(ctx, rbac.RoleAssignment{
		UserID: "teacher-1",
		RoleID: role.ID,
		Scope:  rbac.Scope{Type: "lesson", ID: "lesson-1"},
	}); err != nil {
		t.Fatalf("AssignRole() error = %v", err)
	}

	server := NewServer("learning", manager, nil, nil, SSLConfig{})
	endpoint := &Endpoint{Access: AccessPolicy{
		Authenticated: true,
		ResourceType:  "lesson",
		ResourceParam: "lesson_id",
		Action:        rbac.ActionUpdate,
	}}
	request := mux.SetURLVars(httptest.NewRequest(http.MethodPatch, "/lessons/lesson-1", nil), map[string]string{
		"lesson_id": "lesson-1",
	})
	allowed, err := server.endpointAccess(ctx, endpoint, request, "teacher-1", rbac.ActionUpdate)
	if err != nil || !allowed {
		t.Fatalf("assigned scope access = %v, %v; want true", allowed, err)
	}

	request = mux.SetURLVars(httptest.NewRequest(http.MethodPatch, "/lessons/lesson-2", nil), map[string]string{
		"lesson_id": "lesson-2",
	})
	allowed, err = server.endpointAccess(ctx, endpoint, request, "teacher-1", rbac.ActionUpdate)
	if err != nil || allowed {
		t.Fatalf("different scope access = %v, %v; want false", allowed, err)
	}

	manager.Resolver = resourceResolverFunc(func(_ context.Context, resource rbac.ResourceRef) (*rbac.ResourceRef, error) {
		if resource == (rbac.ResourceRef{Type: "lesson", ID: "lesson-2"}) {
			return &rbac.ResourceRef{Type: "guide", ID: "guide-1"}, nil
		}
		return nil, nil
	})
	manager.Inheritance = rbac.ActionInheritancePolicy{rbac.ActionUpdate: true}
	if err := manager.AssignRole(ctx, rbac.RoleAssignment{
		UserID: "teacher-2",
		RoleID: role.ID,
		Scope:  rbac.Scope{Type: "guide", ID: "guide-1"},
	}); err != nil {
		t.Fatalf("AssignRole() inherited scope error = %v", err)
	}
	allowed, err = server.endpointAccess(ctx, endpoint, request, "teacher-2", rbac.ActionUpdate)
	if err != nil || !allowed {
		t.Fatalf("inherited scope access = %v, %v; want true", allowed, err)
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
