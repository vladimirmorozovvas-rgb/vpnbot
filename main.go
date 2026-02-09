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

var (
	botToken     = mustGetEnv("TELEGRAM_BOT_TOKEN")
	botPassword  = mustGetEnv("BOT_PASSWORD")
	panelURL     = mustGetEnv("PANEL_URL")      // http://ваш_ip:2053 (без слеша в конце!)
	panelUser    = mustGetEnv("PANEL_USERNAME") // admin
	panelPass    = mustGetEnv("PANEL_PASSWORD") // пароль от панели
	vlessHost    = mustGetEnv("VLESS_HOST")
	vlessPort    = mustGetEnv("VLESS_PORT")
	vlessSNI     = mustGetEnv("VLESS_SNI")
	securityType = getEnv("SECURITY_TYPE", "tls")
	publicKey    = getEnv("REALITY_PUBLIC_KEY", "")
	shortID      = getEnv("REALITY_SHORT_ID", "")

	states = make(map[int64]*UserState)
	mu     sync.RWMutex
)

type UserState struct {
	Authenticated bool
	Name          string
}

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
	ID       int             `json:"id"`
	Port     int             `json:"port"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"` // Не используется, но нужен для парсинга
}

type InboundsList struct {
	Success bool      `json:"success"`
	Obj     []Inbound `json:"obj"`
}

// ClientSettings — структура клиента для сериализации в строку
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
	mu.RLock()
	state, exists := states[userID]
	mu.RUnlock()
	if !exists {
		state = &UserState{}
		mu.Lock()
		states[userID] = state
		mu.Unlock()
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

// Авторизация в панели с сохранением кук
func panelLogin() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания cookie jar: %v", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
	}

	loginURL := panelURL + "/login"
	reqBody, _ := json.Marshal(PanelLoginReq{
		Username: panelUser,
		Password: panelPass,
	})

	resp, err := client.Post(loginURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("ошибка подключения к панели: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("статус %d при логине: %s", resp.StatusCode, string(body))
	}

	var result PanelResp
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ошибка парсинга ответа логина: %v", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("авторизация не удалась: %s", result.Msg)
	}

	cookies := jar.Cookies(mustParseURL(panelURL))
	if len(cookies) == 0 {
		return nil, fmt.Errorf("куки не получены после логина")
	}

	return client, nil
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Fatalf("Ошибка парсинга URL %s: %v", rawURL, err)
	}
	return u
}

// Получение списка inbound-конфигураций
func getInbounds(client *http.Client) ([]Inbound, error) {
	apiURL := panelURL + "/panel/api/inbounds/list"

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса списка: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка запроса списка inbound: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("статус %d при получении inbound: %s", resp.StatusCode, string(body))
	}

	var result InboundsList
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ошибка парсинга списка inbound: %v. Тело: %s", err, string(body))
	}

	if !result.Success {
		return nil, fmt.Errorf("запрос списка inbound не удался")
	}

	return result.Obj, nil
}

// Добавление клиента в панель (КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ: settings как СТРОКА)
func addClientToPanel(email, clientUUID string) error {
	client, err := panelLogin()
	if err != nil {
		return fmt.Errorf("авторизация: %v", err)
	}

	// Получаем список inbound и ищем первый VLESS
	inbounds, err := getInbounds(client)
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
		return fmt.Errorf("не найден VLESS inbound. Доступны: %v", protocols)
	}

	// 1. Формируем структуру клиента
	clientSettings := ClientSettings{
		ID:         clientUUID,
		Flow:       "xtls-rprx-vision-udp443", // оставляем пустым для VLESS
		Email:      email,
		LimitIP:    0,    // без ограничения по IP
		TotalGB:    0,    // без лимита трафика
		ExpiryTime: 0,    // без срока действия
		Enable:     true, // активен
		TgID:       "",   // без привязки к Telegram
		SubID:      "",   // без subscription ID
	}

	// 2. Оборачиваем в {"clients": [...]}
	clientsWrapper := map[string][]ClientSettings{
		"clients": {clientSettings},
	}

	// 3. СЕРИАЛИЗУЕМ В СТРОКУ (ключевое исправление!)
	settingsStr, err := json.Marshal(clientsWrapper)
	if err != nil {
		return fmt.Errorf("ошибка сериализации клиентов: %v", err)
	}

	// 4. Формируем основной запрос: поле "settings" — это СТРОКА, а не объект!
	// ВАЖНО: именно так ожидает старая версия панели
	reqBody, err := json.Marshal(map[string]interface{}{
		"id":       targetInbound.ID,
		"settings": string(settingsStr), // ← СТРОКА с экранированным JSON
	})
	if err != nil {
		return fmt.Errorf("ошибка сериализации запроса: %v", err)
	}

	// 5. Правильный путь для вашей панели (единственное число "inbound")
	apiURL := panelURL + "/panel/inbound/addClient"

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

	// Отладка (раскомментируйте для диагностики)
	// log.Printf("📤 Запрос к %s", apiURL)
	// log.Printf("📤 Тело запроса: %s", string(reqBody))
	// log.Printf("📥 Статус ответа: %d", resp.StatusCode)
	// log.Printf("📥 Тело ответа: %s", string(body))

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

func buildVLESSURI(clientUUID, name string) string {
	u := url.URL{
		Scheme: "vless",
		User:   url.User(clientUUID),
		Host:   vlessHost + ":" + vlessPort,
	}

	q := u.Query()
	q.Set("encryption", "none")
	q.Set("security", securityType)
	q.Set("type", "tcp")
	q.Set("sni", vlessSNI)
	q.Set("fp", "chrome")

	if securityType == "reality" && publicKey != "" {
		q.Set("pbk", publicKey)
		if shortID != "" {
			q.Set("sid", shortID)
		}
	}

	u.RawQuery = q.Encode()
	u.Fragment = url.PathEscape(name + " @ " + vlessHost)
	return u.String()
}

func generateQR(text string) ([]byte, error) {
	return qrcode.Encode(text, qrcode.Medium, 320)
}

func main() {
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatal("❌ Ошибка инициализации бота:", err)
	}
	bot.Debug = false
	log.Printf("✅ Бот запущен как @%s", bot.Self.UserName)

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

		// Шаг 1: Аутентификация паролем
		if !state.Authenticated {
			cleanInput := strings.TrimSpace(text)
			cleanExpected := strings.TrimSpace(botPassword)

			if subtle.ConstantTimeCompare([]byte(cleanInput), []byte(cleanExpected)) == 1 {
				state.Authenticated = true
				msg := tgbotapi.NewMessage(chatID, "✅ Пароль верный!\nВведите имя для нового клиента (латиница, без спецсимволов):")
				bot.Send(msg)
			} else {
				msg := tgbotapi.NewMessage(chatID, "❌ Неверный пароль. Попробуйте снова:")
				bot.Send(msg)
			}
			continue
		}

		// Шаг 2: Валидация и сохранение имени
		if state.Name == "" {
			if !isValidClientName(text) {
				msg := tgbotapi.NewMessage(chatID, "❌ Имя должно содержать только буквы, цифры и подчёркивания (латиница, 3-32 символа). Попробуйте снова:")
				bot.Send(msg)
				continue
			}

			state.Name = text
			msg := tgbotapi.NewMessage(chatID, "⏳ Добавляю клиента '"+text+"' на сервер...\nПодождите 5-10 секунд.")
			bot.Send(msg)

			// Генерация UUID
			clientUUID, err := generateUUID()
			if err != nil {
				msg := tgbotapi.NewMessage(chatID, "❌ Ошибка генерации UUID: "+err.Error())
				bot.Send(msg)
				state.Name = ""
				continue
			}

			// Добавление в панель
			err = addClientToPanel(text, clientUUID)
			if err != nil {
				msg := tgbotapi.NewMessage(chatID, "❌ Ошибка добавления клиента:\n"+err.Error()+"\n\n💡 Проверьте:\n• Логин/пароль панели в .env\n• Существует ли VLESS inbound в панели\n• Версию панели (требуется строка в поле settings)")
				bot.Send(msg)
				state.Name = ""
				log.Printf("Ошибка добавления клиента %s: %v", text, err)
				continue
			}

			// Генерация конфигурации
			uri := buildVLESSURI(clientUUID, text)
			qrData, err := generateQR(uri)
			if err != nil {
				msg := tgbotapi.NewMessage(chatID, "❌ Ошибка генерации QR-кода: "+err.Error())
				bot.Send(msg)
				continue
			}

			// Отправка результатов
			photo := tgbotapi.NewPhoto(chatID, tgbotapi.FileBytes{
				Name:  "vless_" + text + ".png",
				Bytes: qrData,
			})
			photo.Caption = fmt.Sprintf("✅ Клиент '%s' успешно добавлен!\n\n📱 Отсканируйте QR-код в клиенте (v2rayNG, SingBox, Shadowrocket)", text)
			bot.Send(photo)

			uriMsg := tgbotapi.NewMessage(chatID, "🔗 Ссылка для ручного импорта:\n```\n"+uri+"\n```")
			uriMsg.ParseMode = "Markdown"
			bot.Send(uriMsg)

			//Сброс состояния для нового клиента
			//Раскомментируйте, если хотите создавать несколько клиентов подряд:
			state.Name = ""
			continue
		}
	}
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
