package identityprovider

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/pocket-id/pocket-id/backend/internal/appconfig"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/httpserver"
	"github.com/pocket-id/pocket-id/backend/internal/model"
)

// callbackPath is the single redirect URI shared by all identity providers
// The provider a callback belongs to is taken from the encrypted state cookie, so admins can register the URI before the provider exists in Pocket ID
const callbackPath = "/api/identity-providers/callback"

type TokenService interface {
	GenerateAccessToken(user model.User, authenticationMethod string, sessionDuration time.Duration) (string, error)
}

type AuditLogger interface {
	Create(ctx context.Context, event model.AuditLogEvent, ipAddress, userAgent, userID string, data model.AuditLogData, tx *gorm.DB) (model.AuditLog, bool)
	CreateSignInEventWithEmail(ctx context.Context, event model.AuditLogEvent, data model.AuditLogData, ipAddress, userAgent, userID string, tx *gorm.DB, emailLoginNotificationEnabled bool) model.AuditLog
}

type UserCreator interface {
	CreateUserInternal(ctx context.Context, dbConfig *appconfig.AppConfigModel, input dto.UserCreateDto, isLdapSync bool, tx *gorm.DB) (model.User, error)
}

// ScimSyncScheduler schedules SCIM after users were created or updated from an identity provider
type ScimSyncScheduler interface {
	ScheduleSync(ctx context.Context)
}

type Dependencies struct {
	DB         *gorm.DB
	HTTPClient *http.Client
	// AppURL is the public URL of Pocket ID, used to build the redirect URI registered at the identity providers
	AppURL string
	// EncryptionKey is the master key the login state cookie encryption key is derived from
	EncryptionKey []byte

	Signer      TokenService
	AuditLog    AuditLogger
	UserCreator UserCreator
	AppConfig   appconfig.AppConfigResolver
	ScimSync    ScimSyncScheduler
}

type Module struct {
	service *Service
	handler *handler
}

func New(deps Dependencies) (*Module, error) {
	service, err := newService(deps)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity provider service: %w", err)
	}

	return &Module{
		service: service,
		handler: newHandler(service, deps.AppConfig),
	}, nil
}

// RegisterRoutes mounts the identity provider endpoints
// adminAuth guards the management routes, userAuth the routes a signed-in user manages their own links with, optionalUserAuth identifies the user on the callback when linking, and loginRateLimit throttles the public sign-in routes
func (m *Module) RegisterRoutes(apiGroup *gin.RouterGroup, adminAuth, userAuth, optionalUserAuth, loginRateLimit gin.HandlerFunc) {
	providers := apiGroup.Group("/identity-providers")

	// Public sign-in routes
	providers.GET("/public", httpserver.Handle(m.handler.listPublic))
	providers.POST("/:id/login", loginRateLimit, httpserver.Handle(m.handler.startLogin))
	providers.GET("/callback", loginRateLimit, optionalUserAuth, httpserver.Handle(m.handler.callback))

	// Linking an external account to the signed-in user
	providers.POST("/:id/link", userAuth, httpserver.Handle(m.handler.startLink))
	apiGroup.GET("/users/me/identity-provider-links", userAuth, httpserver.Handle(m.handler.listOwnLinks))
	apiGroup.DELETE("/users/me/identity-provider-links/:linkId", userAuth, httpserver.Handle(m.handler.deleteOwnLink))

	// Administration
	providers.GET("", adminAuth, httpserver.Handle(m.handler.list))
	providers.POST("", adminAuth, httpserver.Handle(m.handler.create))
	providers.GET("/:id", adminAuth, httpserver.Handle(m.handler.get))
	providers.PUT("/:id", adminAuth, httpserver.Handle(m.handler.update))
	providers.DELETE("/:id", adminAuth, httpserver.Handle(m.handler.delete))
	apiGroup.GET("/users/:id/identity-provider-links", adminAuth, httpserver.Handle(m.handler.listUserLinks))
	apiGroup.DELETE("/users/:id/identity-provider-links/:linkId", adminAuth, httpserver.Handle(m.handler.deleteUserLink))
}
