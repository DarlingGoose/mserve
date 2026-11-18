package mserve

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/DarlingGoose/rbac"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3gen"
)

type Endpoint struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Methods     []string         `json:"methods"`
	Path        string           `json:"path"`
	Handler     http.HandlerFunc `json:"-"`
	Internal    bool             `json:"internal"`
	Request     Request          `json:"request"`
	Scope       string
	Responses   []Response   `json:"responses"`
	Roles       []Role       `json:"roles"`
	Access      AccessPolicy `json:"access"`
	Prefix      bool
}

// AccessPolicy defines how an endpoint is exposed. Every endpoint must either
// set Public, set Authenticated, or declare legacy Roles. ResourceType and
// ResourceParam turn an authenticated policy into a concrete RBAC check. For
// example, ResourceType "lesson" and ResourceParam "lesson_id" authorize the
// resource "<service>.lesson.<lesson_id>".
type AccessPolicy struct {
	Public        bool        `json:"public,omitempty"`
	Authenticated bool        `json:"authenticated,omitempty"`
	ResourceType  string      `json:"resource_type,omitempty"`
	ResourceParam string      `json:"resource_param,omitempty"`
	Action        rbac.Action `json:"action,omitempty"`
}

func (e *Endpoint) validateAccessPolicy() error {
	policy := e.Access
	if policy.Public && policy.Authenticated {
		return fmt.Errorf("endpoint %q cannot be both public and authenticated", e.Path)
	}
	if policy.Public && (policy.ResourceType != "" || policy.ResourceParam != "" || policy.Action != "") {
		return fmt.Errorf("public endpoint %q cannot declare an RBAC resource or action", e.Path)
	}
	if policy.Public && len(e.Roles) > 0 {
		return fmt.Errorf("public endpoint %q cannot declare roles", e.Path)
	}
	if policy.ResourceParam != "" && policy.ResourceType == "" {
		return fmt.Errorf("endpoint %q resource parameter requires a resource type", e.Path)
	}
	if policy.ResourceParam != "" && !strings.Contains(e.Path, "{"+policy.ResourceParam+"}") {
		return fmt.Errorf("endpoint %q does not contain resource parameter %q", e.Path, policy.ResourceParam)
	}
	if (policy.ResourceType != "" || policy.ResourceParam != "" || policy.Action != "") && !policy.Authenticated {
		return fmt.Errorf("endpoint %q RBAC policy must require authentication", e.Path)
	}
	if !policy.Public && !policy.Authenticated && len(e.Roles) == 0 {
		return fmt.Errorf("endpoint %q requires an explicit access policy", e.Path)
	}
	return nil
}

type Request struct {
	Params  map[string]ROption `json:"params"`
	Headers map[string]ROption `json:"headers"`
	Body    interface{}        `json:"body"`
}

type Response struct {
	Status  int                `json:"status"`
	Message string             `json:"message"`
	Body    interface{}        `json:"body"`
	Headers map[string]ROption `json:"headers"`
}

type ROption struct {
	Description string   `json:"description"`
	Default     string   `json:"default"`
	Required    bool     `json:"required"`
	Type        string   `json:"type"`
	Enum        []string `json:"enum"`
}

type Role struct {
	Role   string      `json:"role"`
	Access rbac.Action `json:"access"`
}

func (e *Endpoint) Init(ctx context.Context, service string, manager *rbac.Manager) error {
	if err := e.validateAccessPolicy(); err != nil {
		return err
	}
	if manager == nil {
		if len(e.Roles) > 0 || e.Access.ResourceType != "" || e.Access.Action != "" {
			return fmt.Errorf("endpoint %q requires an RBAC manager", e.Path)
		}
		return nil
	}
	for _, role := range e.Roles {
		//todo check if permission exists by resource
		for _, m := range e.Methods {
			resource := endpointResourceName(service, e.Path)
			if e.Access.ResourceType != "" {
				resource = scopedResourceName(service, e.Access.ResourceType, "**")
			}
			p := &rbac.Permission{
				Resource:  resource,
				Action:    role.Access,
				CreatedAt: time.Now().Unix(),
			}
			if p.Action == "" {
				p.Action = e.Access.Action
			}
			if p.Action == "" {
				p.Action = httpMethodToAction(m)
			}
			_ = manager.CreatePermission(ctx, p)
			r, err := manager.Roles.GetRoleByName(ctx, role.Role)
			if err != nil || r == nil {
				r = &rbac.Role{
					Name:        role.Role,
					Description: "",
					CreatedAt:   time.Now().Unix(),
				}
				err = manager.Roles.CreateRole(ctx, r)
				if err != nil {
					return err
				}
			}
			if r == nil {
				slog.Error("failed to find role", "role", role.Role)
				continue
			}
			err = manager.AssignPermissionToRole(ctx, r.ID, p.ID)
			if err != nil {
				continue
			}
		}

	}
	return nil
}

func GenerateOpenAPI(server *Server, endpoints []Endpoint) (*openapi3.T, error) {
	doc := &openapi3.T{
		OpenAPI: "3.0.3", // Spec version
		Info: &openapi3.Info{
			Title:       server.ServiceName + " API",
			Version:     server.Version,
			Description: "Auto-generated from Go structs",
		},
		Paths:      openapi3.NewPaths(),
		Components: &openapi3.Components{Schemas: openapi3.Schemas{}},
		Servers:    openapi3.Servers{},
		Security: openapi3.SecurityRequirements{
			{},
		},
	}
	allowedOrigins := server.allowedOriginsSnapshot()
	if len(allowedOrigins) == 0 {
		doc.Servers = append(doc.Servers, &openapi3.Server{
			URL: fmt.Sprintf("http://127.0.0.1:%d", server.SSLConfig.Port),
		})
	}
	for _, endpoint := range allowedOrigins {
		doc.Servers = append(doc.Servers, &openapi3.Server{
			URL: endpoint,
		})
	}

	// 1) Register all necessary schemas in components.schemas
	// It's best to register concrete, named Go structs that represent your
	// request/response bodies or other common data structures.
	// `openapi3gen.NewSchemaRefForValue` infers the schema and a title from the type.
	// We'll skip primitive types here as they often don't need to be named components.
	schemasToRegister := []interface{}{
		// Add any specific request/response body structs you use
		// Example: MyRequestBodyStruct{}, MyResponseBodyStruct{},
	}
	for _, endpoint := range endpoints {
		if endpoint.Internal {
			continue
		}
		if endpoint.Request.Body != nil {
			schemasToRegister = append(schemasToRegister, endpoint.Request.Body)
		}
		for _, r := range endpoint.Responses {
			if r.Body != nil {
				schemasToRegister = append(schemasToRegister, r.Body)
			}
		}
	}

	for _, sample := range schemasToRegister {

		ref, err := openapi3gen.NewSchemaRefForValue(sample, nil)
		if err != nil {
			return nil, fmt.Errorf("schema generation for %T: %w", sample, err)
		}
		// openapi3gen usually infers the Go struct name as the schema title.
		// If the title is empty (e.g., for basic types like string, int, or anonymous structs),
		// it might not be suitable for a named component schema.
		if ref.Value.Title != "" {
			doc.Components.Schemas[ref.Value.Title] = ref
		} else {
			ref.Value.Title = GetStructName(sample)
			if ref.Value.Title == "" {
				continue
			}
			doc.Components.Schemas[ref.Value.Title] = ref
		}
	}

	// For rbac.Action, if it's a string or integer alias, `openapi3gen` will correctly
	// create a simple schema. If you want it as a named component (e.g., "Action"),
	// you would explicitly add it and perhaps set a custom title if `ref.Value.Title`
	// isn't what you desire for a basic type alias.
	// For now, it's implicitly handled if used in `Role` or other structs.

	// 2) Build each path & operation
	for _, ep := range endpoints {
		if ep.Internal {
			continue
		}
		pi := &openapi3.PathItem{}
		for _, method := range ep.Methods {
			op := &openapi3.Operation{
				Summary:     ep.Description,
				OperationID: ep.Name,
				Parameters:  openapi3.Parameters{},
				Responses:   openapi3.NewResponses(),
			}

			// Path parameters
			for name, o := range ep.Request.Params {
				op.Parameters = append(op.Parameters, &openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:        name,
						In:          "path",
						Required:    o.Required,
						Description: o.Description,

						// FIX: Specify the schema type for path parameters.
						// Assuming params are strings as per Request.Params map[string]string.
						Schema: openapi3.NewSchemaRef("", &openapi3.Schema{Type: &openapi3.Types{openapi3.TypeString}}),
					},
				})
			}

			// Header parameters
			for name, o := range ep.Request.Headers {
				op.Parameters = append(op.Parameters, &openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:        name,
						In:          "header",
						Required:    o.Required,
						Description: o.Description,
						// FIX: Specify the schema type for header parameters.
						// Assuming headers are strings as per Request.Headers map[string]string.
						Schema: openapi3.NewSchemaRef("", &openapi3.Schema{Type: &openapi3.Types{openapi3.TypeString}}),
					},
				})
			}

			// Request body
			if ep.Request.Body != nil {
				// Generate schema for the request body.
				// If ep.Request.Body is an interface{}, `openapi3gen` will infer
				// the schema from its concrete runtime type.
				v, found := doc.Components.Schemas[GetStructName(ep.Request.Body)]
				if found {
					op.RequestBody = &openapi3.RequestBodyRef{
						Value: &openapi3.RequestBody{
							Required: true,
							// NewContentWithJSONSchemaRef automatically sets "application/json" content type.
							Content: openapi3.NewContentWithJSONSchemaRef(v),
						},
					}
				} else {
					sch, err := openapi3gen.NewSchemaRefForValue(ep.Request.Body, nil)
					if err != nil {
						return nil, fmt.Errorf("request body schema gen for endpoint %s: %w", ep.Name, err)
					}
					op.RequestBody = &openapi3.RequestBodyRef{
						Value: &openapi3.RequestBody{
							Required: true,
							// NewContentWithJSONSchemaRef automatically sets "application/json" content type.
							Content: openapi3.NewContentWithJSONSchemaRef(sch),
						},
					}
				}
			}

			// Responses
			for _, resp := range ep.Responses {
				var responseContent openapi3.Content
				if resp.Body != nil {
					// Generate schema for the response body.
					sch, err := openapi3gen.NewSchemaRefForValue(resp.Body, nil)
					if err != nil {
						return nil, fmt.Errorf("response body schema gen for endpoint %s status %d: %w", ep.Name, resp.Status, err)
					}
					// NewContentWithSchema creates a map with "application/json" by default,
					// or you can explicitly provide supported media types.
					responseContent = openapi3.NewContentWithSchema(sch.Value, []string{"application/json"})
				} else {
					// If no response body, the content can be empty
					responseContent = openapi3.Content{}
				}

				// Ensure response description is not empty, as it's required for `openapi3.Response`.
				responseDescription := resp.Message
				if responseDescription == "" {
					responseDescription = fmt.Sprintf("Response for status %d", resp.Status)
				}

				op.Responses.Set(fmt.Sprint(resp.Status), &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: &responseDescription, // Must be a pointer to a string
						Content:     responseContent,
					},
				})
			}

			// Attach operation to PathItem based on HTTP method
			switch strings.ToUpper(method) {
			case http.MethodGet:
				pi.Get = op
			case http.MethodPost:
				pi.Post = op
			case http.MethodPut:
				pi.Put = op
			case http.MethodDelete:
				pi.Delete = op
			case http.MethodPatch:
				pi.Patch = op
			case http.MethodHead: // Add other common methods if your API uses them
				pi.Head = op
			case http.MethodOptions:
				pi.Options = op
			// etc...
			default:
				return nil, fmt.Errorf("unsupported HTTP method: %s for endpoint %s", method, ep.Name)
			}
		}
		doc.Paths.Set(ep.Path, pi)
	}

	return doc, nil
}

// GetStructName returns the name of the struct held by the interface.
// If the interface holds a pointer to a struct, it returns the name of the struct it points to.
// If it's not a struct or a pointer to a struct, it returns an empty string.
// GetStructName returns the name of the struct type.
// It handles plain structs, pointers to structs, slices/arrays of structs,
// and slices/arrays of pointers to structs.
func GetStructName(i interface{}) string {
	if i == nil {
		return ""
	}

	// Start with the concrete type of i
	t := reflect.TypeOf(i)

	// If it's a pointer, unwrap it
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	// If it's a slice or array, look at the element type
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		elem := t.Elem()
		// If the element is a pointer, unwrap that too
		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}
		if elem.Kind() == reflect.Struct {
			return elem.Name()
		}
		return ""
	}

	// If it's directly a struct, return its name
	if t.Kind() == reflect.Struct {
		return t.Name()
	}

	// Otherwise, not a struct type we recognize
	return ""
}
