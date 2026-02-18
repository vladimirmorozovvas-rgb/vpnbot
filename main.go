package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	uuid "github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
)

// ==================== КОНФИГУРАЦИЯ СЕРВЕРА ====================

type ServerConfig struct {
	ID                string
	Name              string
	PanelURL          string
	PanelUser         string
	PanelPass         string
	VLESSHost         string
	VLESSPort         string
	VLESSSNI          string
	SecurityType      string
	PublicKey         string
	ShortID           string
	APIVersion        string
	UseStringSettings bool
}

// ==================== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ====================

var (
	botToken    = mustGetEnv("TELEGRAM_BOT_TOKEN")
	botPassword = mustGetEnv("BOT_PASSWORD")

	servers  = make(map[string]*ServerConfig)
	states   = make(map[int64]*UserState)
	statesMu sync.RWMutex
)

// ==================== СОСТОЯНИЕ ПОЛЬЗОВАТЕЛЯ ====================

type UserState struct {
	Authenticated bool
	Name          string
	ServerID      string
}

// ==================== СТРУКТУРЫ ДЛЯ API ПАНЕЛИ ====================

type PanelLoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PanelResp struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj,omitempty"`
}

type Inbound struct {
	ID             int             `json:"id"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings json.RawMessage `json:"streamSettings"`
}

type InboundsList struct {
	Success bool      `json:"success"`
	Obj     []Inbound `json:"obj"`
}

type ClientSettings struct {
	ID         string `json:"id"`
	Flow       string `json:"flow"`
	Email      string `json:"email"`
	LimitIP    int    `json:"limitIp"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
	Enable     bool   `json:"enable"`
	TgID       string `json:"tgId"`
	SubID      string `json:"subId"`
}

// VLESSSettings — для парсинга settings inbound
type VLESSSettings struct {
	Clients []ClientSettings `json:"clients"`
}

// StreamSettings — для парсинга streamSettings
type StreamSettings struct {
	Network     string `json:"network"`
	Security    string `json:"security"`
	TCPSettings struct {
		Header struct {
			Type string `json:"type"`
		} `json:"header"`
	} `json:"tcpSettings"`
	RealitySettings struct {
		PublicKey string `json:"publicKey"`
		ShortID   string `json:"shortId"`
	} `json:"realitySettings"`
	TLSSettings struct {
		ServerName string `json:"serverName"`
	} `json:"tlsSettings"`
}

// ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("❌ Ошибка: переменная окружения %s не установлена", key)
	}
	return value
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getUserState(userID int64) *UserState {
	statesMu.RLock()
	state, exists := states[userID]
	statesMu.RUnlock()
	if !exists {
		state = &UserState{}
		statesMu.Lock()
		states[userID] = state
		statesMu.Unlock()
	}
	return state
}

func generateUUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func isValidClientName(name string) bool {
	if len(name) < 3 || len(name) > 32 {
		return false
	}
	for _, ch := range name {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') {
			return false
		}
	}
	return true
}

// ==================== ИНИЦИАЛИЗАЦИЯ СЕРВЕРОВ ====================

func initServers() {
	// 🇳🇱 НИДЕРЛАНДЫ — версия 2.4.0
	servers["nl"] = &ServerConfig{
		ID:                "nl",
		Name:              "🇳🇱 Нидерланды",
		PanelURL:          mustGetEnv("PANEL_URL_NL"),
		PanelUser:         mustGetEnv("PANEL_USERNAME_NL"),
		PanelPass:         mustGetEnv("PANEL_PASSWORD_NL"),
		VLESSHost:         mustGetEnv("VLESS_HOST_NL"),
		VLESSPort:         mustGetEnv("VLESS_PORT_NL"),
		VLESSSNI:          mustGetEnv("VLESS_SNI_NL"),
		SecurityType:      getEnv("SECURITY_TYPE_NL", "tls"),
		PublicKey:         getEnv("REALITY_PUBLIC_KEY_NL", ""),
		ShortID:           getEnv("REALITY_SHORT_ID_NL", ""),
		APIVersion:        "2.4.0",
		UseStringSettings: false,
	}

	// 🇦🇲 АРМЕНИЯ — версия 1.10.1
	servers["am"] = &ServerConfig{
		ID:                "am",
		Name:              "🇦🇲 Армения",
		PanelURL:          mustGetEnv("PANEL_URL_AM"),
		PanelUser:         mustGetEnv("PANEL_USERNAME_AM"),
		PanelPass:         mustGetEnv("PANEL_PASSWORD_AM"),
		VLESSHost:         mustGetEnv("VLESS_HOST_AM"),
		VLESSPort:         mustGetEnv("VLESS_PORT_AM"),
		VLESSSNI:          mustGetEnv("VLESS_SNI_AM"),
		SecurityType:      getEnv("SECURITY_TYPE_AM", "tls"),
		PublicKey:         getEnv("REALITY_PUBLIC_KEY_AM", ""),
		ShortID:           getEnv("REALITY_SHORT_ID_AM", ""),
		APIVersion:        "1.10.1",
		UseStringSettings: true,
	}
}

// ==================== РАБОТА С ПАНЕЛЬЮ ====================

func panelLogin(cfg *ServerConfig) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания cookie jar: %v", err)
	}

	client := &http.Client{Timeout: 15 * time.Second, Jar: jar}
	loginURL := cfg.PanelURL + "/login"

	reqBody, _ := json.Marshal(PanelLoginReq{
		Username: cfg.PanelUser,
		Password: cfg.PanelPass,
	})

	resp, err := client.Post(loginURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("ошибка подключения к панели %s: %v", cfg.ID, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("🔐 [%s] Логин: статус=%d, тело=%s", cfg.ID, resp.StatusCode, string(body))

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("статус %d при логине в %s: %s", resp.StatusCode, cfg.ID, string(body))
	}

	var result PanelResp
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ошибка парсинга ответа логина %s: %v", cfg.ID, err)
	}

	if !result.Success {
		return nil, fmt.Errorf("авторизация в %s не удалась: %s", cfg.ID, result.Msg)
	}

	return client, nil
}

func getInbounds(client *http.Client, cfg *ServerConfig) ([]Inbound, error) {
	var apiURL string
	if cfg.APIVersion == "1.10.1" {
		apiURL = cfg.PanelURL + "/xui/API/inbounds/"
	} else {
		apiURL = cfg.PanelURL + "/panel/api/inbounds/list"
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса списка: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка запроса списка inbound %s: %v", cfg.ID, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("📋 [%s] Получение inbound: статус=%d", cfg.ID, resp.StatusCode)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("статус %d при получении inbound %s: %s", resp.StatusCode, cfg.ID, string(body))
	}

	var result InboundsList
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ошибка парсинга списка inbound %s: %v", cfg.ID, err)
	}

	if !result.Success {
		return nil, fmt.Errorf("запрос списка inbound %s не удался: %s", cfg.ID, result.Obj)
	}

	// 🔍 Логирование каждого inbound для отладки
	for _, ib := range result.Obj {
		log.Printf("🔍 [%s] Inbound ID=%d, Port=%d, Protocol=%s", cfg.ID, ib.ID, ib.Port, ib.Protocol)
		log.Printf("🔍 [%s] Settings: %s", cfg.ID, string(ib.Settings))
		log.Printf("🔍 [%s] StreamSettings: %s", cfg.ID, string(ib.StreamSettings))
	}

	return result.Obj, nil
}

func addClientToPanel(cfg *ServerConfig, email, clientUUID string) error {
	client, err := panelLogin(cfg)
	if err != nil {
		return fmt.Errorf("авторизация: %v", err)
	}

	inbounds, err := getInbounds(client, cfg)
	if err != nil {
		return fmt.Errorf("получение inbound: %v", err)
	}

	var targetInbound *Inbound
	for i := range inbounds {
		if inbounds[i].Protocol == "vless" {
			targetInbound = &inbounds[i]
			break
		}
	}
	if targetInbound == nil {
		var protocols []string
		for _, ib := range inbounds {
			protocols = append(protocols, fmt.Sprintf("%d:%s", ib.ID, ib.Protocol))
		}
		return fmt.Errorf("не найден VLESS inbound на сервере %s. Доступны: %v", cfg.ID, protocols)
	}

	log.Printf("✅ [%s] Найден VLESS inbound: ID=%d, Port=%d", cfg.ID, targetInbound.ID, targetInbound.Port)

	clientSettings := ClientSettings{
		ID:         clientUUID,
		Flow:       "xtls-rprx-vision-udp443",
		Email:      email,
		LimitIP:    0,
		TotalGB:    0,
		ExpiryTime: 0,
		Enable:     true,
		TgID:       "",
		SubID:      "",
	}

	var reqBody []byte
	var apiURL string

	if cfg.APIVersion == "1.10.1" {
		clientsWrapper := map[string][]ClientSettings{"clients": {clientSettings}}
		settingsStr, err := json.Marshal(clientsWrapper)
		if err != nil {
			return fmt.Errorf("ошибка сериализации клиентов: %v", err)
		}

		reqBody, err = json.Marshal(map[string]interface{}{
			"id":       targetInbound.ID,
			"settings": string(settingsStr),
		})
		if err != nil {
			return fmt.Errorf("ошибка сериализации запроса: %v", err)
		}
		apiURL = cfg.PanelURL + "/xui/API/inbounds/addClient/"
	} else {
		settingsObj := map[string][]ClientSettings{"clients": {clientSettings}}

		reqBody, err = json.Marshal(map[string]interface{}{
			"settings": settingsObj,
		})
		if err != nil {
			return fmt.Errorf("ошибка сериализации запроса: %v", err)
		}
		apiURL = fmt.Sprintf("%s/panel/api/inbounds/addClient/%d", cfg.PanelURL, targetInbound.ID)
	}

	log.Printf("📤 [%s] Запрос к: %s", cfg.ID, apiURL)
	log.Printf("📤 [%s] Тело запроса: %s", cfg.ID, string(reqBody))

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("ошибка создания запроса: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ошибка выполнения запроса: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("📥 [%s] Статус: %d, Тело: %s", cfg.ID, resp.StatusCode, string(body))

	if resp.StatusCode != 200 {
		return fmt.Errorf("статус %d: %s", resp.StatusCode, string(body))
	}

	var result PanelResp
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("ошибка парсинга ответа: %v", err)
	}
	if !result.Success {
		return fmt.Errorf("добавление не удалось: %s", result.Msg)
	}

	return nil
}

// ==================== ГЕНЕРАЦИЯ КОНФИГУРАЦИИ ====================

func buildVLESSURI(cfg *ServerConfig, clientUUID, name string) string {
	u := url.URL{
		Scheme: "vless",
		User:   url.User(clientUUID),
		Host:   cfg.VLESSHost + ":" + cfg.VLESSPort, // ← Только IP:PORT, без http://
	}

	q := u.Query()
	q.Set("encryption", "none")
	q.Set("security", cfg.SecurityType)
	q.Set("type", "tcp")
	q.Set("sni", cfg.VLESSSNI)
	q.Set("fp", "chrome")

	if cfg.SecurityType == "reality" && cfg.PublicKey != "" {
		q.Set("pbk", cfg.PublicKey)
		if cfg.ShortID != "" {
			q.Set("sid", cfg.ShortID)
		}
	}

	u.RawQuery = q.Encode()

	// ✅ Исправлено: просто name + host, без PathEscape (он уже внутри url.String())
	u.Fragment = name + " @ " + cfg.VLESSHost

	uri := u.String()
	log.Printf("🔗 [%s] Сгенерирован URI: %s", cfg.ID, uri)
	return uri
}

func generateQR(text string) ([]byte, error) {
	return qrcode.Encode(text, qrcode.Medium, 320)
}

// ==================== КЛАВИАТУРЫ ====================

func getServerKeyboard() tgbotapi.ReplyKeyboardMarkup {
	markup := tgbotapi.NewReplyKeyboard(
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🇳🇱 Нидерланды"),
			tgbotapi.NewKeyboardButton("🇦🇲 Армения"),
		),
	)
	markup.ResizeKeyboard = true
	markup.OneTimeKeyboard = false
	return markup
}

func getRemoveKeyboard() tgbotapi.ReplyKeyboardRemove {
	return tgbotapi.ReplyKeyboardRemove{}
}

// ==================== MAIN ====================

func main() {
	initServers()

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatal("❌ Ошибка инициализации бота:", err)
	}
	bot.Debug = false
	log.Printf("✅ Бот запущен как @%s", bot.Self.UserName)
	log.Printf("🇳🇱 Нидерланды: версия %s", servers["nl"].APIVersion)
	log.Printf("🇦🇲 Армения: версия %s", servers["am"].APIVersion)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil || update.Message.Text == "" {
			continue
		}

		chatID := update.Message.Chat.ID
		userID := update.Message.From.ID
		text := strings.TrimSpace(update.Message.Text)
		state := getUserState(userID)

		// ========== ШАГ 1: АУТЕНТИФИКАЦИЯ ==========
		if !state.Authenticated {
			cleanInput := strings.TrimSpace(text)
			cleanExpected := strings.TrimSpace(botPassword)

			if subtle.ConstantTimeCompare([]byte(cleanInput), []byte(cleanExpected)) == 1 {
				state.Authenticated = true
				msg := tgbotapi.NewMessage(chatID, "✅ Пароль верный!\n\n🌍 Выберите сервер для создания конфигурации:")
				msg.ReplyMarkup = getServerKeyboard()
				bot.Send(msg)
			} else {
				msg := tgbotapi.NewMessage(chatID, "❌ Неверный пароль. Попробуйте снова:")
				bot.Send(msg)
			}
			continue
		}

		// ========== ШАГ 2: ВЫБОР СЕРВЕРА ==========
		if state.ServerID == "" {
			var selectedID string
			switch text {
			case "🇳🇱 Нидерланды":
				selectedID = "nl"
			case "🇦🇲 Армения":
				selectedID = "am"
			default:
				msg := tgbotapi.NewMessage(chatID, "❌ Пожалуйста, выберите сервер из кнопок ниже:")
				msg.ReplyMarkup = getServerKeyboard()
				bot.Send(msg)
				continue
			}

			state.ServerID = selectedID
			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ Выбрано: %s (v%s)\n\n📝 Введите имя для нового клиента:\n• Только латиница (a-z, A-Z)\n• Цифры и подчёркивание (_)\n• Длина: 3-32 символа", servers[selectedID].Name, servers[selectedID].APIVersion))
			msg.ReplyMarkup = getRemoveKeyboard()
			bot.Send(msg)
			continue
		}

		// ========== ШАГ 3: ВВОД ИМЕНИ И СОЗДАНИЕ КЛИЕНТА ==========
		if state.ServerID != "" && state.Name == "" {
			if !isValidClientName(text) {
				msg := tgbotapi.NewMessage(chatID, "❌ Некорректное имя.\n\nПравила:\n• Только латиница (a-z, A-Z)\n• Цифры и подчёркивание (_)\n• Длина: 3-32 символа\n\nПопробуйте снова:")
				bot.Send(msg)
				continue
			}

			state.Name = text
			serverCfg := servers[state.ServerID]

			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("⏳ Создаю конфигурацию '%s' на сервере %s (v%s)...\nПодождите 5-10 секунд.", text, serverCfg.Name, serverCfg.APIVersion))
			bot.Send(msg)

			clientUUID, err := generateUUID()
			if err != nil {
				msg := tgbotapi.NewMessage(chatID, "❌ Ошибка генерации UUID: "+err.Error())
				bot.Send(msg)
				state.Name = ""
				state.ServerID = ""
				continue
			}

			err = addClientToPanel(serverCfg, text, clientUUID)
			if err != nil {
				msg := tgbotapi.NewMessage(chatID, "❌ Ошибка добавления клиента:\n```\n"+err.Error()+"\n```\n\n💡 Проверьте:\n• Логин/пароль панели в .env\n• Существует ли VLESS inbound\n• Версию панели")
				msg.ParseMode = "Markdown"
				bot.Send(msg)
				log.Printf("❌ Ошибка добавления клиента %s на сервер %s: %v", text, state.ServerID, err)
				state.Name = ""
				state.ServerID = ""
				continue
			}

			uri := buildVLESSURI(serverCfg, clientUUID, text)
			qrData, err := generateQR(uri)
			if err != nil {
				msg := tgbotapi.NewMessage(chatID, "❌ Ошибка генерации QR-кода: "+err.Error())
				bot.Send(msg)
				state.Name = ""
				state.ServerID = ""
				continue
			}

			photo := tgbotapi.NewPhoto(chatID, tgbotapi.FileBytes{
				Name:  "vless_" + state.ServerID + "_" + text + ".png",
				Bytes: qrData,
			})
			photo.Caption = fmt.Sprintf("✅ Клиент *%s* успешно создан!\n\n🌐 Сервер: %s (v%s)\n📱 Отсканируйте QR-код в вашем клиенте:\n• v2rayNG\n• SingBox\n• Shadowrocket\n• Streisand", text, serverCfg.Name, serverCfg.APIVersion)
			photo.ParseMode = "Markdown"
			bot.Send(photo)

			uriMsg := tgbotapi.NewMessage(chatID, "🔗 *Ссылка для ручного импорта:*\n```\n"+uri+"\n```")
			uriMsg.ParseMode = "Markdown"
			bot.Send(uriMsg)

			state.Name = ""
			state.ServerID = ""

			nextMsg := tgbotapi.NewMessage(chatID, "🔄 Хотите создать ещё одну конфигурацию?\n\n🌍 Выберите сервер:")
			nextMsg.ReplyMarkup = getServerKeyboard()
			bot.Send(nextMsg)

			continue
		}
	}
}
