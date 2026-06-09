package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port                        string
	AllowedOrigins              []string
	AllowAllCORS                bool
	DBUser                      string
	DBPassword                  string
	DBHost                      string
	DBPort                      string
	DBName                      string
	DSN                         string
	RedisAddr                   string
	RedisPassword               string
	AgentScheme                 string
	AgentPort                   string
	AgentL4Path                 string
	AgentL4OptionsPath          string
	AgentToken                  string
	AgentTimeoutSeconds         int
	DeployLicenseBaseURL        string
	DeployLicenseTimeoutSeconds int
	MetricsPort                 string
	MetricsBucketPath           string
	MetricsIspBucketPath        string
	MetricsCountryBucketPath    string
	MetricsRefererBucketPath    string
	MetricsURLBucketPath        string
	MetricsServerTrafficPath    string
	MetricsUserAgentBucketPath  string
	MetricsPollIntervalSeconds  int
}

func Load() Config {
	cfg := Config{
		Port:                        "8080",
		AllowAllCORS:                true,
		DBUser:                      "dorian",
		DBPassword:                  "StrongPassword123!",
		DBHost:                      "127.0.0.1",
		DBPort:                      "3306",
		DBName:                      "cdnproxy",
		RedisAddr:                   "127.0.0.1:6379",
		RedisPassword:               "",
		AgentScheme:                 "http",
		AgentPort:                   "5000",
		AgentL4Path:                 "/API/L4/l4_firewall_data",
		AgentL4OptionsPath:          "/API/L4/options",
		AgentTimeoutSeconds:         3,
		DeployLicenseBaseURL:        "http://127.0.0.1:9090",
		// Remote create_server runs SSH/SCP + deploy.sh; 30s is too short and causes duplicate deploys when clients retry.
		DeployLicenseTimeoutSeconds: 900,
		MetricsPort:                 "9000",
		MetricsBucketPath:           "/ip_request_stats",
		MetricsIspBucketPath:        "/isp_request_stats",
		MetricsCountryBucketPath:    "/country_request_stats",
		MetricsRefererBucketPath:    "/referer_request_stats",
		MetricsURLBucketPath:        "/url_request_stats",
		MetricsServerTrafficPath:    "/server_traffic_stats",
		MetricsUserAgentBucketPath:  "/useragent_request_stats",
		MetricsPollIntervalSeconds:  30,
	}

	configPath := strings.TrimSpace(os.Getenv("CONFIG_FILE"))
	if configPath == "" {
		configPath = "config.json"
	}
	if fileCfg, err := loadFileConfig(configPath); err == nil && fileCfg != nil {
		applyFileConfig(&cfg, *fileCfg)
	}

	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		cfg.Port = port
	}
	if dbUser := strings.TrimSpace(os.Getenv("DB_USER")); dbUser != "" {
		cfg.DBUser = dbUser
	}
	if os.Getenv("DB_PASSWORD") != "" {
		cfg.DBPassword = os.Getenv("DB_PASSWORD")
	}
	if dbHost := strings.TrimSpace(os.Getenv("DB_HOST")); dbHost != "" {
		cfg.DBHost = dbHost
	}
	if dbPort := strings.TrimSpace(os.Getenv("DB_PORT")); dbPort != "" {
		cfg.DBPort = dbPort
	}
	if dbName := strings.TrimSpace(os.Getenv("DB_NAME")); dbName != "" {
		cfg.DBName = dbName
	}
	if dsn := strings.TrimSpace(os.Getenv("DB_DSN")); dsn != "" {
		cfg.DSN = dsn
	}
	if addr := strings.TrimSpace(os.Getenv("REDIS_ADDR")); addr != "" {
		cfg.RedisAddr = addr
	}
	if os.Getenv("REDIS_PASSWORD") != "" {
		cfg.RedisPassword = os.Getenv("REDIS_PASSWORD")
	}
	if agentScheme := strings.TrimSpace(os.Getenv("AGENT_SCHEME")); agentScheme != "" {
		cfg.AgentScheme = agentScheme
	}
	if agentPort := strings.TrimSpace(os.Getenv("AGENT_PORT")); agentPort != "" {
		cfg.AgentPort = agentPort
	}
	if agentL4Path := strings.TrimSpace(os.Getenv("AGENT_L4_PATH")); agentL4Path != "" {
		cfg.AgentL4Path = agentL4Path
	}
	if agentL4OptionsPath := strings.TrimSpace(os.Getenv("AGENT_L4_OPTIONS_PATH")); agentL4OptionsPath != "" {
		cfg.AgentL4OptionsPath = agentL4OptionsPath
	}
	if os.Getenv("AGENT_TOKEN") != "" {
		cfg.AgentToken = os.Getenv("AGENT_TOKEN")
	}
	if timeoutRaw := strings.TrimSpace(os.Getenv("AGENT_TIMEOUT_SECONDS")); timeoutRaw != "" {
		if parsed, err := strconv.Atoi(timeoutRaw); err == nil && parsed > 0 {
			cfg.AgentTimeoutSeconds = parsed
		}
	}
	if deployURL := strings.TrimSpace(os.Getenv("DEPLOY_LICENSE_BASE_URL")); deployURL != "" {
		cfg.DeployLicenseBaseURL = deployURL
	}
	if timeoutRaw := strings.TrimSpace(os.Getenv("DEPLOY_LICENSE_TIMEOUT_SECONDS")); timeoutRaw != "" {
		if parsed, err := strconv.Atoi(timeoutRaw); err == nil && parsed > 0 {
			cfg.DeployLicenseTimeoutSeconds = parsed
		}
	}

	if metricsPort := strings.TrimSpace(os.Getenv("METRICS_PORT")); metricsPort != "" {
		cfg.MetricsPort = metricsPort
	}
	if metricsBucketPath := strings.TrimSpace(os.Getenv("METRICS_BUCKET_PATH")); metricsBucketPath != "" {
		cfg.MetricsBucketPath = metricsBucketPath
	}
	if metricsIspBucketPath := strings.TrimSpace(os.Getenv("METRICS_ISP_BUCKET_PATH")); metricsIspBucketPath != "" {
		cfg.MetricsIspBucketPath = metricsIspBucketPath
	}
	if metricsCountryBucketPath := strings.TrimSpace(os.Getenv("METRICS_COUNTRY_BUCKET_PATH")); metricsCountryBucketPath != "" {
		cfg.MetricsCountryBucketPath = metricsCountryBucketPath
	}
	if metricsRefererBucketPath := strings.TrimSpace(os.Getenv("METRICS_REFERER_BUCKET_PATH")); metricsRefererBucketPath != "" {
		cfg.MetricsRefererBucketPath = metricsRefererBucketPath
	}
	if metricsURLBucketPath := strings.TrimSpace(os.Getenv("METRICS_URL_BUCKET_PATH")); metricsURLBucketPath != "" {
		cfg.MetricsURLBucketPath = metricsURLBucketPath
	}
	if metricsServerTrafficPath := strings.TrimSpace(os.Getenv("METRICS_SERVER_TRAFFIC_PATH")); metricsServerTrafficPath != "" {
		cfg.MetricsServerTrafficPath = metricsServerTrafficPath
	}
	if metricsUserAgentBucketPath := strings.TrimSpace(os.Getenv("METRICS_USERAGENT_BUCKET_PATH")); metricsUserAgentBucketPath != "" {
		cfg.MetricsUserAgentBucketPath = metricsUserAgentBucketPath
	}
	if pollRaw := strings.TrimSpace(os.Getenv("METRICS_POLL_INTERVAL_SECONDS")); pollRaw != "" {
		if parsed, err := strconv.Atoi(pollRaw); err == nil && parsed > 0 {
			cfg.MetricsPollIntervalSeconds = parsed
		}
	}

	if origins := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS")); origins != "" {
		cfg.AllowedOrigins = splitAndTrim(origins)
		cfg.AllowAllCORS = false
	}

	if len(cfg.AllowedOrigins) == 0 && !cfg.AllowAllCORS {
		cfg.AllowAllCORS = true
	}

	return cfg
}

func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

type fileConfig struct {
	Port                        *string  `json:"port"`
	AllowedOrigins              []string `json:"allowedOrigins"`
	AllowAllCORS                *bool    `json:"allowAllCors"`
	DBUser                      *string  `json:"dbUser"`
	DBPassword                  *string  `json:"dbPassword"`
	DBHost                      *string  `json:"dbHost"`
	DBPort                      *string  `json:"dbPort"`
	DBName                      *string  `json:"dbName"`
	DSN                         *string  `json:"dsn"`
	RedisAddr                   *string  `json:"redisAddr"`
	RedisPassword               *string  `json:"redisPassword"`
	AgentScheme                 *string  `json:"agentScheme"`
	AgentPort                   *string  `json:"agentPort"`
	AgentL4Path                 *string  `json:"agentL4Path"`
	AgentL4OptionsPath          *string  `json:"agentL4OptionsPath"`
	AgentToken                  *string  `json:"agentToken"`
	AgentTimeoutSeconds         *int     `json:"agentTimeoutSeconds"`
	DeployLicenseBaseURL        *string  `json:"deployLicenseBaseURL"`
	DeployLicenseTimeoutSeconds *int     `json:"deployLicenseTimeoutSeconds"`
	MetricsPort                 *string  `json:"metricsPort"`
	MetricsBucketPath           *string  `json:"metricsBucketPath"`
	MetricsIspBucketPath        *string  `json:"metricsIspBucketPath"`
	MetricsCountryBucketPath    *string  `json:"metricsCountryBucketPath"`
	MetricsRefererBucketPath    *string  `json:"metricsRefererBucketPath"`
	MetricsURLBucketPath        *string  `json:"metricsURLBucketPath"`
	MetricsServerTrafficPath    *string  `json:"metricsServerTrafficPath"`
	MetricsUserAgentBucketPath  *string  `json:"metricsUserAgentBucketPath"`
	MetricsPollIntervalSeconds  *int     `json:"metricsPollIntervalSeconds"`
}

func loadFileConfig(path string) (*fileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg fileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyFileConfig(cfg *Config, fileCfg fileConfig) {
	if fileCfg.Port != nil && strings.TrimSpace(*fileCfg.Port) != "" {
		cfg.Port = strings.TrimSpace(*fileCfg.Port)
	}
	if fileCfg.AllowedOrigins != nil {
		cfg.AllowedOrigins = fileCfg.AllowedOrigins
		if len(fileCfg.AllowedOrigins) > 0 {
			cfg.AllowAllCORS = false
		}
	}
	if fileCfg.AllowAllCORS != nil {
		cfg.AllowAllCORS = *fileCfg.AllowAllCORS
	}
	if fileCfg.DBUser != nil && strings.TrimSpace(*fileCfg.DBUser) != "" {
		cfg.DBUser = strings.TrimSpace(*fileCfg.DBUser)
	}
	if fileCfg.DBPassword != nil {
		cfg.DBPassword = *fileCfg.DBPassword
	}
	if fileCfg.DBHost != nil && strings.TrimSpace(*fileCfg.DBHost) != "" {
		cfg.DBHost = strings.TrimSpace(*fileCfg.DBHost)
	}
	if fileCfg.DBPort != nil && strings.TrimSpace(*fileCfg.DBPort) != "" {
		cfg.DBPort = strings.TrimSpace(*fileCfg.DBPort)
	}
	if fileCfg.DBName != nil && strings.TrimSpace(*fileCfg.DBName) != "" {
		cfg.DBName = strings.TrimSpace(*fileCfg.DBName)
	}
	if fileCfg.DSN != nil && strings.TrimSpace(*fileCfg.DSN) != "" {
		cfg.DSN = strings.TrimSpace(*fileCfg.DSN)
	}
	if fileCfg.RedisAddr != nil && strings.TrimSpace(*fileCfg.RedisAddr) != "" {
		cfg.RedisAddr = strings.TrimSpace(*fileCfg.RedisAddr)
	}
	if fileCfg.RedisPassword != nil {
		cfg.RedisPassword = *fileCfg.RedisPassword
	}
	if fileCfg.AgentScheme != nil && strings.TrimSpace(*fileCfg.AgentScheme) != "" {
		cfg.AgentScheme = strings.TrimSpace(*fileCfg.AgentScheme)
	}
	if fileCfg.AgentPort != nil && strings.TrimSpace(*fileCfg.AgentPort) != "" {
		cfg.AgentPort = strings.TrimSpace(*fileCfg.AgentPort)
	}
	if fileCfg.AgentL4Path != nil && strings.TrimSpace(*fileCfg.AgentL4Path) != "" {
		cfg.AgentL4Path = strings.TrimSpace(*fileCfg.AgentL4Path)
	}
	if fileCfg.AgentL4OptionsPath != nil && strings.TrimSpace(*fileCfg.AgentL4OptionsPath) != "" {
		cfg.AgentL4OptionsPath = strings.TrimSpace(*fileCfg.AgentL4OptionsPath)
	}
	if fileCfg.AgentToken != nil {
		cfg.AgentToken = *fileCfg.AgentToken
	}
	if fileCfg.AgentTimeoutSeconds != nil && *fileCfg.AgentTimeoutSeconds > 0 {
		cfg.AgentTimeoutSeconds = *fileCfg.AgentTimeoutSeconds
	}
	if fileCfg.DeployLicenseBaseURL != nil && strings.TrimSpace(*fileCfg.DeployLicenseBaseURL) != "" {
		cfg.DeployLicenseBaseURL = strings.TrimSpace(*fileCfg.DeployLicenseBaseURL)
	}
	if fileCfg.DeployLicenseTimeoutSeconds != nil && *fileCfg.DeployLicenseTimeoutSeconds > 0 {
		cfg.DeployLicenseTimeoutSeconds = *fileCfg.DeployLicenseTimeoutSeconds
	}
	if fileCfg.MetricsPort != nil && strings.TrimSpace(*fileCfg.MetricsPort) != "" {
		cfg.MetricsPort = strings.TrimSpace(*fileCfg.MetricsPort)
	}
	if fileCfg.MetricsBucketPath != nil && strings.TrimSpace(*fileCfg.MetricsBucketPath) != "" {
		cfg.MetricsBucketPath = strings.TrimSpace(*fileCfg.MetricsBucketPath)
	}
	if fileCfg.MetricsIspBucketPath != nil && strings.TrimSpace(*fileCfg.MetricsIspBucketPath) != "" {
		cfg.MetricsIspBucketPath = strings.TrimSpace(*fileCfg.MetricsIspBucketPath)
	}
	if fileCfg.MetricsCountryBucketPath != nil && strings.TrimSpace(*fileCfg.MetricsCountryBucketPath) != "" {
		cfg.MetricsCountryBucketPath = strings.TrimSpace(*fileCfg.MetricsCountryBucketPath)
	}
	if fileCfg.MetricsRefererBucketPath != nil && strings.TrimSpace(*fileCfg.MetricsRefererBucketPath) != "" {
		cfg.MetricsRefererBucketPath = strings.TrimSpace(*fileCfg.MetricsRefererBucketPath)
	}
	if fileCfg.MetricsURLBucketPath != nil && strings.TrimSpace(*fileCfg.MetricsURLBucketPath) != "" {
		cfg.MetricsURLBucketPath = strings.TrimSpace(*fileCfg.MetricsURLBucketPath)
	}
	if fileCfg.MetricsServerTrafficPath != nil && strings.TrimSpace(*fileCfg.MetricsServerTrafficPath) != "" {
		cfg.MetricsServerTrafficPath = strings.TrimSpace(*fileCfg.MetricsServerTrafficPath)
	}
	if fileCfg.MetricsUserAgentBucketPath != nil && strings.TrimSpace(*fileCfg.MetricsUserAgentBucketPath) != "" {
		cfg.MetricsUserAgentBucketPath = strings.TrimSpace(*fileCfg.MetricsUserAgentBucketPath)
	}
	if fileCfg.MetricsPollIntervalSeconds != nil && *fileCfg.MetricsPollIntervalSeconds > 0 {
		cfg.MetricsPollIntervalSeconds = *fileCfg.MetricsPollIntervalSeconds
	}
}
