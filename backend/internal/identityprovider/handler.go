package identityprovider

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"github.com/pocket-id/pocket-id/backend/internal/appconfig"
	"github.com/pocket-id/pocket-id/backend/internal/apperror"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/httpserver"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
	"github.com/pocket-id/pocket-id/backend/internal/utils/cookie"
)

// errorQueryParam carries the error code to the page the browser is sent to when a flow fails
// Only the stable code is passed, so the frontend shows its own translated message instead of text taken from the URL
const errorQueryParam = "identityProviderError"

type handler struct {
	service   *Service
	appConfig appconfig.AppConfigResolver
}

func newHandler(service *Service, appConfig appconfig.AppConfigResolver) *handler {
	return &handler{service: service, appConfig: appConfig}
}

// list godoc
// @Summary List identity providers
// @Description Get a paginated list of the external OpenID Connect providers users can sign in with
// @Tags Identity Providers
// @Produce json
// @Param search query string false "Search term to filter identity providers by name or issuer"
// @Param pagination[page] query int false "Page number for pagination" default(1)
// @Param pagination[limit] query int false "Number of items per page" default(20)
// @Param sort[column] query string false "Column to sort by"
// @Param sort[direction] query string false "Sort direction (asc or desc)" default("asc")
// @Success 200 {object} dto.Paginated[identityProviderDto]
// @Router /api/identity-providers [get]
func (h *handler) list(c *gin.Context) error {
	providers, pagination, err := h.service.List(c.Request.Context(), c.Query("search"), utils.ParseListRequestOptions(c))
	if err != nil {
		return err
	}

	items := make([]identityProviderDto, len(providers))
	for i, provider := range providers {
		items[i] = newIdentityProviderDto(provider)
	}

	c.JSON(http.StatusOK, dto.Paginated[identityProviderDto]{
		Data:       items,
		Pagination: pagination,
	})
	return nil
}

// get godoc
// @Summary Get identity provider
// @Description Get an identity provider by ID
// @Tags Identity Providers
// @Produce json
// @Param id path string true "Identity provider ID"
// @Success 200 {object} identityProviderDto
// @Router /api/identity-providers/{id} [get]
func (h *handler) get(c *gin.Context) error {
	provider, err := h.service.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, newIdentityProviderDto(provider))
	return nil
}

// create godoc
// @Summary Create identity provider
// @Description Add an external OpenID Connect provider users can sign in with
// @Tags Identity Providers
// @Accept json
// @Produce json
// @Param identityProvider body identityProviderInputDto true "Identity provider"
// @Success 201 {object} identityProviderDto
// @Router /api/identity-providers [post]
func (h *handler) create(c *gin.Context) error {
	var input identityProviderInputDto
	err := httpserver.BindJSON(c, &input)
	if err != nil {
		return err
	}

	provider, err := h.service.Create(c.Request.Context(), input)
	if err != nil {
		return err
	}

	c.JSON(http.StatusCreated, newIdentityProviderDto(provider))
	return nil
}

// update godoc
// @Summary Update identity provider
// @Description Update an identity provider, keeping the client secret when none is sent
// @Tags Identity Providers
// @Accept json
// @Produce json
// @Param id path string true "Identity provider ID"
// @Param identityProvider body identityProviderInputDto true "Identity provider"
// @Success 200 {object} identityProviderDto
// @Router /api/identity-providers/{id} [put]
func (h *handler) update(c *gin.Context) error {
	var input identityProviderInputDto
	err := httpserver.BindJSON(c, &input)
	if err != nil {
		return err
	}

	provider, err := h.service.Update(c.Request.Context(), c.Param("id"), input)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, newIdentityProviderDto(provider))
	return nil
}

// delete godoc
// @Summary Delete identity provider
// @Description Delete an identity provider along with all accounts linked to it
// @Tags Identity Providers
// @Param id path string true "Identity provider ID"
// @Success 204 "No Content"
// @Router /api/identity-providers/{id} [delete]
func (h *handler) delete(c *gin.Context) error {
	err := h.service.Delete(c.Request.Context(), c.Param("id"))
	if err != nil {
		return err
	}

	c.Status(http.StatusNoContent)
	return nil
}

// listPublic godoc
// @Summary List enabled identity providers
// @Description Get the identity providers shown on the sign-in page
// @Tags Identity Providers
// @Produce json
// @Success 200 {array} publicIdentityProviderDto
// @Router /api/identity-providers/public [get]
func (h *handler) listPublic(c *gin.Context) error {
	providers, err := h.service.ListEnabled(c.Request.Context())
	if err != nil {
		return err
	}

	items := make([]publicIdentityProviderDto, len(providers))
	for i, provider := range providers {
		items[i] = publicIdentityProviderDto{ID: provider.ID, Name: provider.Name}
	}

	c.JSON(http.StatusOK, items)
	return nil
}

// startLogin godoc
// @Summary Start sign-in with identity provider
// @Description Prepare a sign-in with an identity provider and return the URL the browser has to be sent to
// @Tags Identity Providers
// @Accept json
// @Produce json
// @Param id path string true "Identity provider ID"
// @Param body body startDto true "Where to go after signing in"
// @Success 200 {object} startResponseDto
// @Router /api/identity-providers/{id}/login [post]
func (h *handler) startLogin(c *gin.Context) error {
	var input startDto
	err := httpserver.BindJSON(c, &input)
	if err != nil {
		return err
	}

	authURL, state, err := h.service.StartLogin(c.Request.Context(), c.Param("id"), input.Redirect)
	if err != nil {
		return err
	}

	cookie.AddIdentityProviderStateCookie(c, int(loginStateTTL.Seconds()), callbackPath, state)
	c.JSON(http.StatusOK, startResponseDto{URL: authURL})
	return nil
}

// startLink godoc
// @Summary Start linking an external account
// @Description Prepare linking an account at an identity provider to the signed-in user and return the URL the browser has to be sent to
// @Tags Identity Providers
// @Produce json
// @Param id path string true "Identity provider ID"
// @Success 200 {object} startResponseDto
// @Router /api/identity-providers/{id}/link [post]
func (h *handler) startLink(c *gin.Context) error {
	authURL, state, err := h.service.StartLink(c.Request.Context(), c.Param("id"), c.GetString("userID"))
	if err != nil {
		return err
	}

	cookie.AddIdentityProviderStateCookie(c, int(loginStateTTL.Seconds()), callbackPath, state)
	c.JSON(http.StatusOK, startResponseDto{URL: authURL})
	return nil
}

// callback godoc
// @Summary Identity provider callback
// @Description The redirect URI of all identity providers, which completes the sign-in or link flow and redirects the browser back into Pocket ID
// @Tags Identity Providers
// @Param state query string true "State"
// @Param code query string false "Authorization code"
// @Param iss query string false "Issuer of the authorization response"
// @Param error query string false "Error returned by the identity provider"
// @Success 302 "Redirect"
// @Router /api/identity-providers/callback [get]
func (h *handler) callback(c *gin.Context) error {
	// The state cookie is single-use, so remove it before anything else
	stateCookie, _ := c.Cookie(cookie.IdentityProviderStateCookieName)
	cookie.ClearIdentityProviderStateCookie(c, callbackPath)

	dbConfig, err := h.appConfig.GetConfig(c.Request.Context())
	if err != nil {
		return fmt.Errorf("error loading app configuration: %w", err)
	}

	result, err := h.service.HandleCallback(c.Request.Context(), dbConfig, callbackInput{
		State:          c.Query("state"),
		Code:           c.Query("code"),
		Issuer:         c.Query("iss"),
		Error:          c.Query("error"),
		StateCookie:    stateCookie,
		SignedInUserID: c.GetString("userID"),
		IPAddress:      c.ClientIP(),
		UserAgent:      c.Request.UserAgent(),
	})
	if err != nil {
		c.Redirect(http.StatusFound, errorRedirect(c, result, err))
		return nil
	}

	// A completed link returns to the account settings, which confirm it to the user
	if result.Mode == flowModeLink {
		c.Redirect(http.StatusFound, accountSettingsPath+"?identityProviderLinked=true")
		return nil
	}

	maxAge := int(dbConfig.SessionDuration.AsDurationMinutes().Seconds())
	cookie.AddAccessTokenCookie(c, maxAge, result.AccessToken)
	c.Redirect(http.StatusFound, result.Redirect)
	return nil
}

// errorRedirect returns the page a failed flow is sent to, with the error code for the frontend to display
// Errors without a client-safe code are logged here, since the redirect hides them from the error middleware
func errorRedirect(c *gin.Context, result callbackResult, err error) string {
	code := apperror.CodeInternal
	var appErr *apperror.Error
	if errors.As(err, &appErr) {
		code = appErr.Code()
	}
	if code == apperror.CodeInternal || errors.Unwrap(err) != nil {
		slog.WarnContext(c.Request.Context(), "Identity provider flow failed", slog.String("error_code", string(code)), slog.Any("error", err))
	}

	query := url.Values{errorQueryParam: {string(code)}}
	if result.Mode == flowModeLink {
		return accountSettingsPath + "?" + query.Encode()
	}

	// Failed sign-ins return to the sign-in page, keeping the original destination so the user can try again
	if result.Redirect != "" && result.Redirect != defaultRedirect {
		query.Set("redirect", result.Redirect)
	}
	return "/login?" + query.Encode()
}

// listOwnLinks godoc
// @Summary List own linked accounts
// @Description Get the external accounts linked to the signed-in user
// @Tags Identity Providers
// @Produce json
// @Success 200 {array} linkDto
// @Router /api/users/me/identity-provider-links [get]
func (h *handler) listOwnLinks(c *gin.Context) error {
	return h.respondWithLinks(c, c.GetString("userID"))
}

// deleteOwnLink godoc
// @Summary Unlink own external account
// @Description Remove the link between the signed-in user and an external account
// @Tags Identity Providers
// @Param linkId path string true "Link ID"
// @Success 204 "No Content"
// @Router /api/users/me/identity-provider-links/{linkId} [delete]
func (h *handler) deleteOwnLink(c *gin.Context) error {
	return h.deleteLink(c, c.GetString("userID"))
}

// listUserLinks godoc
// @Summary List linked accounts of a user
// @Description Get the external accounts linked to a user
// @Tags Identity Providers
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {array} linkDto
// @Router /api/users/{id}/identity-provider-links [get]
func (h *handler) listUserLinks(c *gin.Context) error {
	return h.respondWithLinks(c, c.Param("id"))
}

// deleteUserLink godoc
// @Summary Unlink external account of a user
// @Description Remove the link between a user and an external account
// @Tags Identity Providers
// @Param id path string true "User ID"
// @Param linkId path string true "Link ID"
// @Success 204 "No Content"
// @Router /api/users/{id}/identity-provider-links/{linkId} [delete]
func (h *handler) deleteUserLink(c *gin.Context) error {
	return h.deleteLink(c, c.Param("id"))
}

func (h *handler) respondWithLinks(c *gin.Context, userID string) error {
	links, err := h.service.ListLinks(c.Request.Context(), userID)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, newLinkDtos(links))
	return nil
}

func (h *handler) deleteLink(c *gin.Context, userID string) error {
	err := h.service.DeleteLink(c.Request.Context(), userID, c.Param("linkId"), c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		return err
	}

	c.Status(http.StatusNoContent)
	return nil
}
