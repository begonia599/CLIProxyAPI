package management

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Cloud Code API constants
const (
	cloudCodeBaseURL    = "https://daily-cloudcode-pa.googleapis.com"
	cloudCodeFallback   = "https://cloudcode-pa.googleapis.com"
	fetchModelsPath     = "/v1internal:fetchAvailableModels"
	loadCodeAssistPath  = "/v1internal:loadCodeAssist"
	quotaUserAgent      = "antigravity/1.104.0 darwin/arm64"
	quotaClientID       = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
	quotaClientSecret   = "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"
	quotaRequestTimeout = 15 * time.Second
)

type quotaModelInfo struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Remaining float64 `json:"remaining"`
	ResetTime string  `json:"resetTime,omitempty"`
}

type quotaAccountInfo struct {
	Email    string           `json:"email"`
	Plan     string           `json:"plan,omitempty"`
	Tier     string           `json:"tier,omitempty"`
	Error    string           `json:"error,omitempty"`
	Models   []quotaModelInfo `json:"models,omitempty"`
	Disabled bool             `json:"disabled"`
	AuthID   string           `json:"authId,omitempty"`
}

// GetAntigravityQuota fetches Cloud Code quota for all Antigravity accounts.
func (h *Handler) GetAntigravityQuota(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth manager unavailable"})
		return
	}

	auths := h.authManager.List()
	var agAuths []struct {
		email        string
		refreshToken string
		accessToken  string
		expiry       time.Time
		projectID    string
		disabled     bool
		authID       string
	}

	for _, auth := range auths {
		if auth == nil {
			continue
		}
		provider := strings.TrimSpace(strings.ToLower(auth.Provider))
		if provider != "antigravity" {
			continue
		}
		email := authEmail(auth)
		refreshToken := metaString(auth.Metadata, "refresh_token")
		accessToken := metaString(auth.Metadata, "access_token")
		expiry := metaExpiry(auth.Metadata)
		projectID := metaString(auth.Metadata, "project_id")
		if projectID == "" {
			projectID = metaString(auth.Metadata, "projectId")
		}

		if refreshToken == "" && accessToken == "" {
			continue
		}
		agAuths = append(agAuths, struct {
			email        string
			refreshToken string
			accessToken  string
			expiry       time.Time
			projectID    string
			disabled     bool
			authID       string
		}{email, refreshToken, accessToken, expiry, projectID, auth.Disabled, auth.ID})
	}

	if len(agAuths) == 0 {
		c.JSON(200, gin.H{"accounts": []quotaAccountInfo{}})
		return
	}

	// Fetch concurrently
	results := make([]quotaAccountInfo, len(agAuths))
	var wg sync.WaitGroup
	for i, ag := range agAuths {
		wg.Add(1)
		go func(idx int, email, refreshToken, accessToken, projectID string, expiry time.Time, disabled bool, authID string) {
			defer wg.Done()
			if disabled {
				results[idx] = quotaAccountInfo{Email: email, Disabled: true, AuthID: authID, Error: "账户已停用"}
				return
			}
			result := fetchAccountQuota(email, refreshToken, accessToken, expiry, projectID)
			result.AuthID = authID
			results[idx] = result
		}(i, ag.email, ag.refreshToken, ag.accessToken, ag.projectID, ag.expiry, ag.disabled, ag.authID)
	}
	wg.Wait()

	c.JSON(200, gin.H{"accounts": results})
}

func fetchAccountQuota(email, refreshToken, accessToken string, expiry time.Time, projectID string) quotaAccountInfo {
	info := quotaAccountInfo{Email: email}

	// Refresh token if expired or missing
	if accessToken == "" || time.Now().After(expiry.Add(-2*time.Minute)) {
		if refreshToken == "" {
			info.Error = "no refresh token"
			return info
		}
		var err error
		accessToken, err = refreshAccessToken(refreshToken)
		if err != nil {
			info.Error = fmt.Sprintf("token refresh failed: %v", err)
			return info
		}
	}

	// Fetch plan info (loadCodeAssist)
	plan, tier, resolvedProject := fetchPlanInfo(accessToken)
	info.Plan = plan
	info.Tier = tier
	if projectID == "" && resolvedProject != "" {
		projectID = resolvedProject
	}

	// Fetch model quota
	models, err := fetchModelsQuota(accessToken, projectID)
	if err != nil {
		info.Error = fmt.Sprintf("fetch models failed: %v", err)
		return info
	}
	info.Models = models
	return info
}

func refreshAccessToken(refreshToken string) (string, error) {
	form := url.Values{}
	form.Set("client_id", quotaClientID)
	form.Set("client_secret", quotaClientSecret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	client := &http.Client{Timeout: quotaRequestTimeout}
	resp, err := client.Post("https://oauth2.googleapis.com/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

func fetchPlanInfo(accessToken string) (plan, tier, projectID string) {
	payload := map[string]any{
		"metadata": map[string]string{
			"ideType":    "ANTIGRAVITY",
			"platform":   "PLATFORM_UNSPECIFIED",
			"pluginType": "GEMINI",
		},
	}

	data, err := cloudCodeRequest(accessToken, loadCodeAssistPath, payload)
	if err != nil {
		log.Debugf("antigravity quota: loadCodeAssist failed: %v", err)
		return "", "", ""
	}

	// Extract plan info
	if paidTier, ok := data["paidTier"].(map[string]any); ok {
		if id, ok := paidTier["id"].(string); ok {
			tier = id
		}
	}
	if tier == "" {
		if currentTier, ok := data["currentTier"].(map[string]any); ok {
			if id, ok := currentTier["id"].(string); ok {
				tier = id
			}
		}
	}

	// Map tier to readable plan name
	plan = tierToPlanName(tier)

	// Extract projectId
	if proj, ok := data["cloudaicompanionProject"].(string); ok {
		projectID = proj
	} else if projMap, ok := data["cloudaicompanionProject"].(map[string]any); ok {
		if id, ok := projMap["id"].(string); ok {
			projectID = id
		}
	}

	return plan, tier, projectID
}

func tierToPlanName(tier string) string {
	t := strings.ToLower(tier)
	switch {
	case strings.Contains(t, "enterprise"):
		return "Enterprise"
	case strings.Contains(t, "business"):
		return "Business"
	case strings.Contains(t, "premium"):
		return "Premium"
	case strings.Contains(t, "pro"):
		return "Pro"
	case strings.Contains(t, "standard"):
		return "Standard"
	case strings.Contains(t, "free"):
		return "Free"
	case tier != "":
		return tier
	default:
		return "Unknown"
	}
}

func fetchModelsQuota(accessToken, projectID string) ([]quotaModelInfo, error) {
	payload := map[string]any{}
	if projectID != "" {
		payload["project"] = projectID
	}

	data, err := cloudCodeRequest(accessToken, fetchModelsPath, payload)
	if err != nil {
		return nil, err
	}

	modelsRaw, ok := data["models"].(map[string]any)
	if !ok {
		return []quotaModelInfo{}, nil
	}

	var models []quotaModelInfo
	for key, v := range modelsRaw {
		info, ok := v.(map[string]any)
		if !ok {
			continue
		}

		m := quotaModelInfo{
			ID:   key,
			Name: key,
		}

		if dn, ok := info["displayName"].(string); ok && dn != "" {
			m.Name = dn
		}
		if model, ok := info["model"].(string); ok && model != "" {
			m.ID = model
		}

		if qi, ok := info["quotaInfo"].(map[string]any); ok {
			if rf, ok := qi["remainingFraction"].(float64); ok {
				m.Remaining = rf * 100 // Convert to percentage
			}
			if rt, ok := qi["resetTime"].(string); ok {
				m.ResetTime = rt
			}
		}

		models = append(models, m)
	}

	return models, nil
}

func cloudCodeRequest(accessToken, path string, payload map[string]any) (map[string]any, error) {
	bodyBytes, _ := json.Marshal(payload)

	// Try primary, then fallback
	for _, baseURL := range []string{cloudCodeBaseURL, cloudCodeFallback} {
		url := baseURL + path
		req, err := http.NewRequest("POST", url, strings.NewReader(string(bodyBytes)))
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", quotaUserAgent)

		client := &http.Client{Timeout: quotaRequestTimeout}
		resp, err := client.Do(req)
		if err != nil {
			log.Debugf("antigravity quota: request to %s failed: %v", url, err)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return nil, fmt.Errorf("auth error (HTTP %d)", resp.StatusCode)
		}
		if resp.StatusCode != 200 {
			log.Debugf("antigravity quota: %s returned %d: %s", url, resp.StatusCode, string(body))
			continue
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("invalid JSON response: %w", err)
		}
		return result, nil
	}

	return nil, fmt.Errorf("all Cloud Code endpoints failed")
}

// Helper: extract string from metadata map
func metaString(meta map[string]any, key string) string {
	if meta == nil {
		return ""
	}
	if v, ok := meta[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// Helper: extract token expiry from metadata
func metaExpiry(meta map[string]any) time.Time {
	if meta == nil {
		return time.Time{}
	}
	// Try "expired" field (RFC3339)
	if v, ok := meta["expired"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
	}
	// Try timestamp + expires_in
	if ts, ok := meta["timestamp"].(float64); ok {
		if ei, ok := meta["expires_in"].(float64); ok {
			return time.UnixMilli(int64(ts)).Add(time.Duration(ei) * time.Second)
		}
	}
	return time.Time{}
}
