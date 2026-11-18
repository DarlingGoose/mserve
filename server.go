package mserve

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DarlingGoose/credentials/oauth/oclient"
	"github.com/DarlingGoose/credentials/oauth/oserver"
	"github.com/DarlingGoose/mserve/nuxt3FromOpenApi"
	"github.com/DarlingGoose/rbac/rbacServer"
	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"

	"github.com/DarlingGoose/credentials/session"

	"github.com/DarlingGoose/credentials/user"
	"github.com/DarlingGoose/rbac"
	"github.com/caddyserver/certmagic"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel/sdk/metric"
)

// Server wraps HTTP server, router, RBAC manager, and CertMagic domains
// plus dynamic CORS origins and OpenTelemetry metrics
type Server struct {
	ServiceName    string
	Description    string
	Version        string
	rbac           *rbac.Manager
	router         *mux.Router
	domains        []string
	allowedOrigins []string
	muOrigins      sync.RWMutex
	sessionClient  *session.Client

	SSLConfig       SSLConfig
	healthCheckPath string
	endpoints       []Endpoint
	// tp              *trace.TracerProvider
	mr *metric.MeterProvider
	// rootEnabled bool
}

// NewServer creates a new Server instance
func NewServer(serviceName string, r *rbac.Manager, domains []string, sessionClient *session.Client, ssl SSLConfig) *Server {
	router := mux.NewRouter()
	if serviceName == "" {
		serviceName = "default"
	}
	if ssl.DefaultHostName == "" {
		ssl.DefaultHostName = "localhost"
	}
	s := &Server{
		rbac:           r,
		ServiceName:    serviceName,
		router:         router,
		domains:        domains,
		allowedOrigins: []string{},
		muOrigins:      sync.RWMutex{},
		sessionClient:  sessionClient,
		SSLConfig:      ssl,
	}
	router.Use(s.corsMiddleware)
	return s
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin, _ := s.matchOrigin(r)
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE,HEAD, OPTIONS")
		w.Header().Set(
			"Access-Control-Allow-Headers",
			"Content-Type, Authorization, Authentication-Key, Range, Content-Range, X-WebAuthn-Session-ID",
		)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set(
			"Access-Control-Expose-Headers",
			"X-WebAuthn-Session-ID, Accept-Ranges, Content-Range, Content-Length",
		)
		// handle preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getOrigin(r *http.Request) string {
	return strings.TrimSuffix(r.Header.Get("Origin"), "/")
}

func (s *Server) matchOrigin(r *http.Request) (string, error) {
	origin := getOrigin(r)
	if origin == "" {
		return "", nil
	}
	for _, o := range s.allowedOriginsSnapshot() {
		if strings.EqualFold(o, origin) {
			return origin, nil
		}
	}
	return "", fmt.Errorf("invalid origin %s", origin)
}

func (s *Server) allowedOriginsSnapshot() []string {
	s.muOrigins.RLock()
	defer s.muOrigins.RUnlock()
	return append([]string(nil), s.allowedOrigins...)
}

// AddMiddleware sets up dynamic CORS
func (s *Server) AddMiddleware(lists ...func(next http.Handler) http.Handler) {
	for _, list := range lists {
		s.router.Use(list)
	}
}

// AddOrigin dynamically adds a new CORS origin
func (s *Server) AddOrigin(origin string) {
	s.muOrigins.Lock()
	defer s.muOrigins.Unlock()
	for _, o := range s.allowedOrigins {
		if o == origin {
			return
		}
	}
	s.allowedOrigins = append(s.allowedOrigins, origin)
}

func pathToTitle(path string) string {
	// 1) Trim any leading/trailing slashes
	s := strings.Trim(path, "/")

	// 2) Split on "/", "-", or "_" into words
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == '/' || r == '-' || r == '_'
	})

	// 3) Title-case each word (ASCII-only)
	for i, w := range words {
		if w == "" {
			continue
		}
		// Uppercase first byte, lowercase the rest
		words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
	}

	// 4) Join back together with spaces
	return strings.Join(words, " ")
}

// AddEndpoints registers endpoints on the router
func (s *Server) AddEndpoints(ctx context.Context, endpoints ...*Endpoint) error {
	// s.sessionClient.Authenticate()
	// session.SetSessionCookie()
	for _, e := range endpoints {
		if e.Path == "" {
			return fmt.Errorf("empty path")
		}
		if e.Handler == nil {
			return fmt.Errorf("nil handler")
		}
		if e.Name == "" {
			e.Name = pathToTitle(e.Path)
		}
		if len(e.Methods) == 0 {
			if e.Request.Body != nil {
				e.Methods = []string{http.MethodPost}
			} else {
				e.Methods = []string{http.MethodGet}
			}
		} else if len(e.Methods) == 1 && e.Methods[0] == http.MethodGet && e.Request.Body != nil {
			e.Methods[0] = http.MethodPost
		}
		if err := e.validateAccessPolicy(); err != nil {
			return err
		}
		if (len(e.Roles) > 0 || e.Access.ResourceType != "" || e.Access.Action != "") && e.Access.Action == "" {
			for _, method := range e.Methods {
				if httpMethodToAction(method) == "" {
					return fmt.Errorf("endpoint %q has no RBAC action mapping for HTTP method %q", e.Path, method)
				}
			}
		}

		handler := s.authorizeEndpoint(e)
		err := e.Init(ctx, s.ServiceName, s.rbac)
		if err != nil {
			return err
		}
		m := append(e.Methods, http.MethodOptions)
		if e.Prefix {
			s.router.
				PathPrefix(e.Path).
				HandlerFunc(handler).
				Methods(m...)
		} else {
			s.router.
				HandleFunc(e.Path, handler).
				Methods(m...)
		}
		s.endpoints = append(s.endpoints, *e)
	}
	return nil
}

func (s *Server) authorizeEndpoint(endpoint *Endpoint) http.HandlerFunc {
	if endpoint.Access.Public {
		return endpoint.Handler
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if s.sessionClient == nil {
			http.Error(w, "authentication is not configured", http.StatusInternalServerError)
			return
		}
		userSession, ctx, err := s.sessionClient.Authenticate(w, r)
		if err != nil || userSession == nil || !userSession.SignedIn {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		needsRBAC := len(endpoint.Roles) > 0 || endpoint.Access.ResourceType != "" || endpoint.Access.Action != ""
		if needsRBAC {
			if s.rbac == nil {
				http.Error(w, "authorization is not configured", http.StatusInternalServerError)
				return
			}
			resource, resourceErr := s.endpointResource(endpoint, r)
			if resourceErr != nil {
				http.Error(w, resourceErr.Error(), http.StatusBadRequest)
				return
			}
			action := endpoint.Access.Action
			if action == "" {
				action = httpMethodToAction(r.Method)
			}
			if !s.hasAccess(ctx, resource, userSession.UserID, action) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		endpoint.Handler(w, r.WithContext(ctx))
	}
}

func (s *Server) endpointResource(endpoint *Endpoint, r *http.Request) (string, error) {
	if endpoint.Access.ResourceType == "" {
		return endpointResourceName(s.ServiceName, endpoint.Path), nil
	}
	resourceID := ""
	if endpoint.Access.ResourceParam != "" {
		resourceID = mux.Vars(r)[endpoint.Access.ResourceParam]
		if resourceID == "" {
			return "", fmt.Errorf("missing resource parameter %q", endpoint.Access.ResourceParam)
		}
	}
	return scopedResourceName(s.ServiceName, endpoint.Access.ResourceType, resourceID), nil
}

func scopedResourceName(service, resourceType, resourceID string) string {
	parts := []string{strings.Trim(service, "."), strings.Trim(resourceType, ".")}
	if resourceID != "" {
		parts = append(parts, url.PathEscape(resourceID))
	}
	return strings.Join(parts, ".")
}

// httpMethodToAction corrects PATCH and DELETE handling in rbac v1.0.19 and
// fails closed for methods without a CRUD mapping.
func httpMethodToAction(method string) rbac.Action {
	switch method {
	case http.MethodGet, http.MethodHead:
		return rbac.ActionRead
	case http.MethodPost:
		return rbac.ActionCreate
	case http.MethodPut, http.MethodPatch:
		return rbac.ActionUpdate
	case http.MethodDelete:
		return rbac.ActionDelete
	default:
		return ""
	}
}

// OTEL_METRICS_EXPORTER
// OTEL_EXPORTER_OTLP_PROTOCOL
// OTEL_EXPORTER_OTLP_METRICS_PROTOCOL
// OTEL_EXPORTER_PROMETHEUS_HOST
// OTEL_EXPORTER_PROMETHEUS_PORT
// SetupMetrics initializes OpenTelemetry metrics and mounts /metrics endpoint
func (s *Server) SetupMetrics() *Server {
	//tp, mr, err := initTracer()
	//if err != nil {
	//	slog.Error("failed to init tracer", "error", err)
	//	return s
	//}
	//s.router.Use(otelmux.Middleware(s.ServiceName))
	//s.tp = tp
	//s.mr = mr
	return s
}

type SSLConfig struct {
	Email           string
	Agreed          bool
	Enabled         bool
	Port            int
	DefaultHostName string
}

// Run starts the server with CertMagic and OpenTelemetry
func (s *Server) Run(ctx context.Context) error {
	certmagic.DefaultACME.Agreed = s.SSLConfig.Agreed
	certmagic.DefaultACME.Email = s.SSLConfig.Email
	rootHandler := s.router
	// rootHandler := otelhttp.NewHandler(s.router, "http-server")
	go func() {
		if !s.SSLConfig.Enabled {
			if s.SSLConfig.Port <= 0 {
				s.SSLConfig.Port = 8081
			}
			slog.Info("starting http server",
				"host", "http://"+s.SSLConfig.DefaultHostName+":"+strconv.Itoa(s.SSLConfig.Port))
			if err := http.ListenAndServe(":"+strconv.Itoa(s.SSLConfig.Port), rootHandler); err != nil {
				log.Fatalf("failed to start https server: %v", err)
			}
			return
		}
		slog.Info("starting https server")
		if err := certmagic.HTTPS(s.domains, rootHandler); err != nil {
			log.Fatalf("CertMagic HTTPS failed: %v", err)
		}
	}()
	<-ctx.Done()
	slog.Info("shutting down")
	//if s.tp != nil {
	//	_ = s.tp.Shutdown(context.Background())
	//}
	if s.mr != nil {
		_ = s.mr.Shutdown(context.Background())
	}
	return nil
}

// HealthCheck registers a health check handler
func (s *Server) HealthCheck(path string, f func(ctx context.Context) error) *Server {
	s.healthCheckPath = path
	s.router.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if f == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		if err := f(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return s
}

func (s *Server) Endpoints() []Endpoint {
	return s.endpoints
}

func (s *Server) SetupOServer(ctx context.Context, o oserver.OServer) *Server {
	handler := oserver.NewHandler(o, oserver.ContentTypeJSON)
	err := s.AddEndpoints(ctx, makeEndpoints(handler)...)
	if err != nil {
		slog.Error("failed adding o server endpoints", "err", err)
	}

	return s
}

func (s *Server) SetupSlog(level slog.Level) *Server {
	opts := &slog.HandlerOptions{
		Level: level, // reads the value each log call
	}
	h := NewStackHandler(slog.NewTextHandler(os.Stdout, opts))
	// 2. Set as global
	_ = slog.SetLogLoggerLevel(slog.LevelDebug)
	slog.SetDefault(slog.New(h))
	return s
}

func (s *Server) SetupRbac(ctx context.Context) *Server {
	err := s.AddEndpoints(ctx, makeRBACEndpoints(rbacServer.NewServer(s.rbac))...)
	if err != nil {
		slog.Error("failed adding o server endpoints", "err", err)
	}
	return s
}

func (s *Server) SetupUserLogin(ctx context.Context, userServer *user.Server) *Server {
	err := s.AddEndpoints(ctx, makeUserEndpoints(userServer)...)
	if err != nil {
		slog.Error("failed adding o server endpoints", "err", err)
	}
	// User handlers use this middleware to load the full user record into the
	// request context. Endpoint authentication remains enforced separately.
	s.AddMiddleware(userServer.AuthMiddleware)
	return s
}

func (s *Server) SetupOClient(o oclient.OAuthService) *Server {
	return s
}

func (s *Server) hasAccess(ctx context.Context, resource, userID string, action rbac.Action) bool {
	if endpointResourceName(s.ServiceName, s.healthCheckPath) == resource {
		return true
	}
	can, err := s.rbac.Can(ctx, userID, resource, action)
	if err != nil {
		slog.Error("error checking permissions", "err", err, "user_id", userID, "resource", resource, "action", action)
		return false
	}
	return can
}

func (s *Server) GenerateOpenAPIDocs() *Server {
	api, err := GenerateOpenAPI(s, s.endpoints)
	if err != nil {
		return s
	}

	swaggerUITmpl := template.Must(template.New("swaggerUI").Parse(swaggerUIMasterTemplate))

	_ = s.AddEndpoints(context.Background(), &Endpoint{
		Name:        "OpenAPI",
		Description: "",
		Methods:     []string{"GET"},
		Path:        "/openapi/v2.yaml",
		Handler: func(writer http.ResponseWriter, r *http.Request) {
			if p := r.URL.Query().Get("prefix"); p != "" {
				slog.Info("preix", "o", p)
				var ep []Endpoint
				for _, e := range s.endpoints {
					if strings.Contains(e.Path, p) {
						ep = append(ep, e)
					}
				}

				a, err := GenerateOpenAPI(s, ep)
				if err == nil {
					slog.Info("preix", "o", p, "l", len(ep))
					Docs(writer, r, a, template.Must(template.New("swaggerUI").Parse(swaggerUIMasterTemplate)), p)
					return
				}
			}
			Docs(writer, r, api, swaggerUITmpl, "")
		},
		Internal: false,
		Request: Request{
			Params: map[string]ROption{
				"render": {
					Default:  "",
					Required: false,
					Enum:     []string{"json", "yaml"},
				},
				"prefix": {
					Default:  "",
					Required: false,
				},
			},
			Headers: nil,
			Body:    nil,
		},
		Scope:     "",
		Responses: nil,
		Roles:     nil,
		Access:    AccessPolicy{Public: true},
	})
	_ = s.AddEndpoints(context.Background(), &Endpoint{
		Name:        "Nuxt Plugin",
		Description: "",
		Methods:     []string{"GET"},
		Path:        "/openapi/nuxt/plugins",
		Request: Request{
			Params: map[string]ROption{
				"prefix": {
					Default:  "",
					Required: false,
					Enum:     []string{"json", "yaml"},
				},
			},
			Headers: nil,
			Body:    nil,
		},
		Handler: func(w http.ResponseWriter, r *http.Request) {
			if p := r.URL.Query().Get("prefix"); p != "" {
				var ep []Endpoint
				for _, e := range s.endpoints {
					if strings.Contains(e.Path, p) {
						ep = append(ep, e)
					}
				}
				a, err := GenerateOpenAPI(s, ep)
				if err == nil {
					NuxtPlugin(w, r, a)
					return
				}
			}
			NuxtPlugin(w, r, api)
		},
		Access: AccessPolicy{Public: true},
	})

	return s
}

func NuxtPlugin(w http.ResponseWriter, r *http.Request, api *openapi3.T) {
	d, err := api.MarshalYAML()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw, err := yaml.Marshal(d)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := nuxt3FromOpenApi.GenerateNuxt3Plugin(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript")
	w.Header().Set("Name", nuxt3FromOpenApi.ToPascalCase(api.Info.Title)+".js")
	_, _ = w.Write([]byte(resp))
}

func Docs(w http.ResponseWriter, r *http.Request, api *openapi3.T, swaggerUITmpl *template.Template, prefix string) {
	renderUI := r.URL.Query().Get("render")
	switch renderUI {
	case "json":
		d, err := api.MarshalJSON()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		_, writeErr := w.Write(d)
		if writeErr != nil {
			http.Error(w, "Failed to write JSON: "+writeErr.Error(), http.StatusInternalServerError)
			slog.Error("Error writing JSON", "err", writeErr)
		}
	case "yaml":
		d, err := api.MarshalYAML()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		raw, err := yaml.Marshal(d)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		_, writeErr := w.Write(raw)
		if writeErr != nil {
			http.Error(w, "Failed to write YAML: "+writeErr.Error(), http.StatusInternalServerError)
			slog.Error("Error writing YAML", "err", writeErr)
		}
	default:
		// Serve Swagger UI HTML
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := struct {
			OpenAPIYAMLURL string
		}{
			OpenAPIYAMLURL: "/openapi/v2.yaml?render=yaml" + "&prefix=" + prefix, // Swagger UI will fetch YAML from this path
		}
		if err := swaggerUITmpl.Execute(w, data); err != nil {
			http.Error(w, "Failed to render Swagger UI: "+err.Error(), http.StatusInternalServerError)
			slog.Error("Error writing Swagger UI", "err", err)
		}
	}
}

const swaggerUIMasterTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Swagger UI</title>
    <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.4/swagger-ui.min.css" >
    <link rel="icon" type="image/png" href="https://petstore.swagger.io/favicon-32x32.png" sizes="32x32" />
    <link rel="icon" type="image/png" href="https://petstore.swagger.io/favicon-16x16.png" sizes="16x16" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.4/swagger-ui-bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.4/swagger-ui-standalone-preset.min.js"></script>
    <script>
        window.onload = function() {
            // Begin Swagger UI call
            const ui = SwaggerUIBundle({
                url: "{{.OpenAPIYAMLURL}}", // Placeholder for your OpenAPI YAML endpoint
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
            window.ui = ui;
        };
    </script>
</body>
</html>
`

type ErrorR struct {
	Status    int    `json:"status"`
	Error     string `json:"error"`
	Timestamp string `json:"timestamp"`
}

// WriteError sends a JSON error response.
func WriteError(w http.ResponseWriter, r *http.Request, status int, err string) {
	slog.Error("HTTP error",
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"error", err,
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := ErrorR{
		Status:    status,
		Error:     err,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	WriteBody(w, r, resp)
}

func GetParam(r *http.Request, name string, defaultValue string) string {
	if p := PathParam(r, name); p != "" {
		return p
	}
	if p := QueryParam(r, name); p != "" {
		return p
	}
	return defaultValue
}

func PathParam(r *http.Request, name string) string {
	v, ok := mux.Vars(r)[name]
	if !ok {
		return ""
	}
	return v
}

func QueryParam(r *http.Request, name string) string {
	v := r.URL.Query().Get(name)
	return v
}
