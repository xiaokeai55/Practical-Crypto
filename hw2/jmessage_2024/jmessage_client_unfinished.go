package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"
	//"io/ioutil"
	//"log"
)

// Globals

var (
	serverPort          int
	serverDomain        string
	serverDomainAndPort string
	serverProtocol      string
	noTLS               bool
	strictTLS           bool
	username            string
	password            string
	apiKey              string
	doUserRegister      bool
	headlessMode        bool
	messageIDCounter    int
	attachmentsDir      string
	globalPubKey        PubKeyStruct
	globalPrivKey       PrivKeyStruct
)

type PubKeyStruct struct {
	EncPK string `json:"encPK"`
	SigPK string `json:"sigPK"`
}

type PrivKeyStruct struct {
	EncSK string `json:"encSK"`
	SigSK string `json:"sigSK"`
}

type FilePathStruct struct {
	Path string `json:"path"`
}

type APIKeyStruct struct {
	APIkey string `json:"APIkey"`
}

type MessageStruct struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Id        int    `json:"id"`
	ReceiptID int    `json:"receiptID"`
	Payload   string `json:"payload"`
	decrypted string
	url       string
	localPath string
}

type UserStruct struct {
	Username     string `json:"username"`
	CreationTime int    `json:"creationTime"`
	CheckedTime  int    `json:"lastCheckedTime"`
}

type CiphertextStruct struct {
	C1  string `json:"C1"`
	C2  string `json:"C2"`
	Sig string `json:"Sig"`
}

// PrettyPrint to print struct in a readable way
func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// Do a POST request and return the result
func doPostRequest(postURL string, postContents []byte) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("POST", postURL, bytes.NewBuffer(postContents))
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the POST request
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Do a GET request and return the result
func doGetRequest(getURL string) (int, []byte, error) {
	// Initialize a client
	client := &http.Client{}
	req, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return 0, nil, err
	}

	// Set up some fake headers
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {"Mozilla/5.0 (Macintosh"},
	}

	// Make the GET request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return 0, nil, err
	}

	// Extract the body contents
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, body, nil
}

// Upload a file to the server
func uploadFileToServer(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadFile/" +
		username + "/" + apiKey

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("filefield", filename)
	io.Copy(part, file)
	writer.Close()

	r, _ := http.NewRequest("POST", posturl, body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	resp, err := client.Do(r)
	defer resp.Body.Close()

	// Read the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// Handle error
		fmt.Println("Error while reading the response bytes:", err)
		return "", err
	}

	// Unmarshal the JSON into a map or a struct
	var resultStruct FilePathStruct
	err = json.Unmarshal(respBody, &resultStruct)
	if err != nil {
		// Handle error
		fmt.Println("Error while parsing JSON:", err)
		return "", err
	}

	// Construct a URL
	fileURL := serverProtocol + "://" + serverDomainAndPort + "/downloadFile" +
		resultStruct.Path

	return fileURL, nil
}

// Download a file from the server and return its local path
func downloadFileFromServer(geturl string, localPath string, key string, hash string) error {
	//1. Downloads the file from the given URL.
	// Get the file data
	resp, err := http.Get(geturl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// no errors; return
	if resp.StatusCode != 200 {
		return errors.New("bad result code")
	}

	encryptedData, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// 	2. Computes `HASH = SHA256(encrypted file)` and verifies that this matches the hash `H` specified in the message. If not, it rejects the attachment.
	computedHash := sha256.Sum256(encryptedData)
	if hex.EncodeToString(computedHash[:]) != hash {
		return errors.New("hash mismatch")
	}

	// 3. Decrypts the message using the key `KEY` using ChaCha20 with IV=0.
	decodedkey, err := b64.StdEncoding.DecodeString(key)
	if err != nil {
		panic(err)
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(decodedkey, make([]byte, 12)) // 12-byte zero IV
	if err != nil {
		panic(err)
	}
	decryptedData := make([]byte, len(encryptedData))
	cipher.XORKeyStream(decryptedData, encryptedData)

	// Create the file
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	if err := os.WriteFile(localPath, decryptedData, 0644); err != nil {
		return fmt.Errorf("failed to write decrypted file: %v", err)
	}
	_, err = io.Copy(out, resp.Body)
	return err
}

// Log in to server
func serverLogin(username string, password string) (string, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/login/" +
		username + "/" + password

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", errors.New("bad result code")
	}

	// Parse JSON into an APIKey struct
	var result APIKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.APIkey, nil
}

// Log in to server
func getPublicKeyFromServer(forUser string) (*PubKeyStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/lookupKey/" + forUser

	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, errors.New("bad result code")
	}

	// Parse JSON into an PubKeyStruct
	var result PubKeyStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return &result, nil
}

// Register username with the server
func registerUserWithServer(username string, password string) error {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/registerUser/" +
		username + "/" + password

	code, _, err := doGetRequest(geturl)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("bad result code")
	}

	return nil
}

// Get messages from the server
func getMessagesFromServer() ([]MessageStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/getMessages/" +
		username + "/" + apiKey

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []MessageStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// TODO: Implement decryption
	decryptMessages(result)

	return result, nil
}

// Get messages from the server
func getUserListFromServer() ([]UserStruct, error) {
	geturl := serverProtocol + "://" + serverDomainAndPort + "/listUsers"

	// Make the request to the server
	code, body, err := doGetRequest(geturl)
	if err != nil {
		return nil, err
	}

	if code != 200 {
		return nil, errors.New("bad result code")
	}

	// Parse JSON into an array of MessageStructs
	var result []UserStruct
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	// Sort the user list by timestamp
	sort.Slice(result, func(i, j int) bool {
		return result[i].CheckedTime > result[j].CheckedTime
	})

	return result, nil
}

// Post a message to the server
func sendMessageToServer(sender string, recipient string, message []byte, readReceiptID int) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
		username + "/" + apiKey

	// Format the message as a JSON object and increment the message ID counter
	msg := MessageStruct{sender, recipient, messageIDCounter, readReceiptID, b64.StdEncoding.EncodeToString(message), "", "", ""}
	messageIDCounter++

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("bad result code")
	}

	return nil
}

// Post a message to the server
func sendAttachmentToServer(recipient string, message string, url string) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/sendMessage/" +
		username + "/" + apiKey

	// First, obtain the recipient's public key
	pubkey, err := getPublicKeyFromServer(recipient)
	if err != nil {
		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
		return err
	}

	encryptedMessage := encryptMessage([]byte(message), username, pubkey)

	// Format the message as a JSON object and increment the message ID counter
	msg := MessageStruct{username, recipient, messageIDCounter, 0, b64.StdEncoding.EncodeToString(encryptedMessage), "", url, ""}
	messageIDCounter++

	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("bad result code")
	}

	return nil
}

// Read in a message from the command line and then send it to the serve
func doReadAndSendMessage(recipient string, messageBody string) error {
	keepReading := true
	reader := bufio.NewReader(os.Stdin)

	// First, obtain the recipient's public key
	pubkey, err := getPublicKeyFromServer(recipient)
	if err != nil {
		fmt.Printf("Could not obtain public key for user %s.\n", recipient)
		return err
	}

	// If there is no message given, we read one in from the user
	if messageBody == "" {
		// Next, read in a multi-line message, ending when we get an empty line (\n)
		fmt.Println("Enter message contents below. Finish the message with a period.")

		for keepReading == true {
			input, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}

			if strings.TrimSpace(input) == "." {
				keepReading = false
			} else {
				messageBody = messageBody + input
			}
		}
	}

	// Now encrypt the message
	encryptedMessage := encryptMessage([]byte(messageBody), username, pubkey)

	// Finally, send the encrypted message to the server
	return sendMessageToServer(username, recipient, []byte(encryptedMessage), 0)
}

// Request a key from the server
func getKeyFromServer(user_key string) {
	geturl := serverProtocol + "://" + serverDomain + ":" + strconv.Itoa(serverPort) + "/lookupKey?" + user_key

	fmt.Println(geturl)
}

// Upload a new public key to the server
func registerPublicKeyWithServer(username string, pubKeyEncoded PubKeyStruct) error {
	posturl := serverProtocol + "://" + serverDomainAndPort + "/uploadKey/" +
		username + "/" + apiKey

	body, err := json.Marshal(pubKeyEncoded)
	if err != nil {
		return err
	}

	// Post it to the server
	code, _, err := doPostRequest(posturl, body)
	if err != nil {
		return err
	}

	if code != 200 {
		return errors.New("Bad result code")
	}

	return nil
}

//******************************
// Cryptography functions
//******************************

// Encrypts a file on disk into a new ciphertext file on disk, returns the HEX encoded key
// and file hash, or an error.
func encryptAttachment(plaintextFilePath string, ciphertextFilePath string) (string, string, error) {
	// TODO: IMPLEMENT

	// 1. First, it selects a random 256-bit ChaCha20 key `KEY`.
	KEY := make([]byte, 32)
	if _, err := rand.Read(KEY); err != nil {
		panic(err)
	}

	// 2. Next it encrypts the file using ChaCha20 under key `KEY` with a zero IV.
	file, err := os.ReadFile(plaintextFilePath)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, 12)
	cipher, err := chacha20.NewUnauthenticatedCipher(KEY, nonce)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(file))
	cipher.XORKeyStream(ciphertext, file)

	// 3. It computes `H = SHA256(encrypted file)`.
	H := sha256.Sum256(ciphertext)

	// 4. It uploads the encrypted file to the JMessage server, and obtains a temporary URL.
	if err := os.WriteFile(ciphertextFilePath, ciphertext, 0644); err != nil {
		panic(err)
	}

	url, err := uploadFileToServer(ciphertextFilePath)
	if err != nil {
		panic(err)
	}

	// 5. It sends a standard encrypted message containing `url, KEY, H` in the following structured plaintext:
	encrypted := fmt.Sprintf(">>>MSGURL=%s?KEY=%s?H=%s", url, b64.StdEncoding.EncodeToString(KEY), hex.EncodeToString(H[:]))

	return encrypted, url, nil
}

func decodePrivateSigningKey(privKey PrivKeyStruct) *ecdsa.PrivateKey {
	var result *ecdsa.PrivateKey

	// TODO: IMPLEMENT

	sigSK, err := b64.StdEncoding.DecodeString(privKey.SigSK)
	if err != nil {
		panic(err)
	}

	prik, err := x509.ParsePKCS8PrivateKey(sigSK)
	if err != nil {
		panic(err)
	}

	result = prik.(*ecdsa.PrivateKey)
	return result
}

// Sign a string using ECDSA
func ECDSASign(message []byte, privKey PrivKeyStruct) []byte {
	// TODO: IMPLEMENT
	sigSK := decodePrivateSigningKey(privKey)

	hash := sha256.Sum256([]byte(message))
	sign, err := ecdsa.SignASN1(rand.Reader, sigSK, hash[:])
	if err != nil {
		panic(err)
	}

	return sign
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func decryptMessage(payload string, senderUsername string, senderPubKey *PubKeyStruct, recipientPrivKey *PrivKeyStruct) ([]byte, error) {
	// TODO: IMPLEMENT

	//Verify the signature `Sig`:

	// 1. The recipient concatenates `C1` and `C2` to form a string `toVerify`.
	var ciphertext CiphertextStruct

	decodedPayload, err := b64.StdEncoding.DecodeString(payload)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal([]byte(decodedPayload), &ciphertext)
	if err != nil {
		panic(err)
	}

	toVerify := ciphertext.C1 + ciphertext.C2
	sig, err := b64.StdEncoding.DecodeString(ciphertext.Sig)
	if err != nil {
		panic(err)
	}

	// 2. The recipient decodes `sigPK` into an ECDSA public key (point on P-256).
	DecodedSigPK, err := b64.StdEncoding.DecodeString(senderPubKey.SigPK)
	if err != nil {
		panic(err)
	}
	sigPK, err := x509.ParsePKIXPublicKey(DecodedSigPK)
	if err != nil {
		panic(err)
	}

	// 3. The recipient verifies the signature `Sig` against message `toVerify` using ECDSA with P-256 under key `sigPK`.
	hash := sha256.Sum256([]byte(toVerify))

	// 4. If the previous check fails, terminate processing and reject.
	if !ecdsa.VerifyASN1(sigPK.(*ecdsa.PublicKey), hash[:], sig) {
		return nil, errors.New("failed to verify \"Sig\"")
	}

	// Decrypt `C1` to obtain `K`:

	// 1. The recipient BASE64-decodes `C1` as a point on P-256.
	c1, err := b64.StdEncoding.DecodeString(ciphertext.C1)
	if err != nil {
		panic(err)
	}

	parsed, err := x509.ParsePKIXPublicKey(c1)
	if err != nil {
		panic(err)
	}

	C1decoded, err := parsed.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		panic(err)
	}

	// 2. The recipient decodes `encSK` as a scalar `s` between `0` and `q-1` (inclusive).
	encSK, err := b64.StdEncoding.DecodeString(recipientPrivKey.EncSK)
	if err != nil {
		panic(err)
	}

	privK, err := x509.ParsePKCS8PrivateKey(encSK)
	if err != nil {
		panic(err)
	}

	s, _ := privK.(*ecdsa.PrivateKey).ECDH()

	// 3. The recipient computes `K = SHA256(s * C1)` where * represents scalar point multiplication.
	ssk, _ := s.ECDH(C1decoded)
	K := sha256.Sum256(ssk)

	// Decrypt `C2` to obtain the plaintext:

	// 1. The recipient BASE46-decodes `C2` as an octet string.
	c2, err := b64.StdEncoding.DecodeString(ciphertext.C2)
	if err != nil {
		panic(err)
	}

	// 2. The recipient deciphers `C2` using ChaCha20 under `K`, using a zero IV to obtain `M'`.
	M, err := chacha20.NewUnauthenticatedCipher(K[:], make([]byte, 12))
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, len(c2))
	M.XORKeyStream(plaintext, c2)

	// 3. The recipient parses `M'` as `username || 0x3A || M || CHECK`, where CHECK is a 4-byte octet string.
	Mprime := plaintext[:len(plaintext)-8]

	// 4. The recipient computes `CHECK' = CRC32(username || 0x3A || M )`. If `CHECK != CHECK'`, abort decryption and reject.
	table := crc32.MakeTable(crc32.IEEE)
	check := crc32.Checksum(Mprime, table)
	if fmt.Sprintf("%08x", check) != string(plaintext[len(plaintext)-8:]) {
		return nil, errors.New("CHECK != CHECK'")
	}

	// 5. If `username != sender_username`, then abort decryption and reject.
	parts := strings.SplitN(string(Mprime), ":", 2)
	if parts[0] != senderUsername {
		return nil, errors.New("username != sender_username")
	}

	// 6. Otherwise, output `M`.

	return []byte(parts[1]), nil
}

// Encrypts a byte string under a (Base64-encoded) public string, and returns a
// byte slice as a result.
func encryptMessage(message []byte, senderUsername string, pubkey *PubKeyStruct) []byte {
	// TODO: IMPLEMENT

	// Compute `C1` and `K`:
	// The sender decodes `encPK` as a point on the P-256 elliptic curve.

	decodeP, err := b64.StdEncoding.DecodeString(pubkey.EncPK)
	if err != nil {
		panic(err)
	}

	parsed, err := x509.ParsePKIXPublicKey(decodeP)
	if err != nil {
		panic(err)
	}

	encPK, err := parsed.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		panic(err)
	}

	// The sender generates a random scalar `c` between `0` and `q-1` (inclusive).
	c, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// The sender computes `epk = cP` using scalar point multiplication.
	epk, err := x509.MarshalPKIXPublicKey(c.PublicKey())
	if err != nil {
		panic(err)
	}

	// The sender computes `ssk = c*encPK` where * represents scalar point multiplication, and encodes the x-coordinate according to SEC 1, Version 2.0, Section 2.3.5.
	ssk, _ := c.ECDH(encPK)

	// // Version 2.0, Section 2.3.5.
	// 5. The sender computes `K = SHA256(ssk)` where * represents scalar point multiplication. This key `K` will be used in the next section.
	K := sha256.Sum256(ssk)

	// 6. The sender encodes `epk` into the value `C1`, by first encoding it using [RFC 5208, Section 4.1] and then BASE64-encoding the result.
	C1 := b64.StdEncoding.EncodeToString(epk)

	// 	Compute `C2`:

	// 1. The sender first constructs a message string `M' = sender_username || 0x3A || M` where `||` represents concatenation, and the byte `0x3A` does not appear in the sender username.
	M := fmt.Sprintf("%s:%s", senderUsername, message)

	// 2. The sender computes `CHECK = CRC32(M')`, where CRC32 uses the IEEE standard polynomial (0xedb88320).
	table := crc32.MakeTable(crc32.IEEE)
	CHECK := crc32.Checksum([]byte(M), table)

	// 3. The sender constructs a message string `M'' = M' || CHECK`.
	Mp := fmt.Sprintf("%s%x", M, CHECK)

	// 4. The sender uses ChaCha20 with an initial state/IV set to 0 to encipher `M''` under key `K`. It encodes the result using BASE64 to produce `C2`.
	nonce := make([]byte, 12)
	cipher, err := chacha20.NewUnauthenticatedCipher(K[:], nonce)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(Mp))
	cipher.XORKeyStream(ciphertext, []byte(Mp))

	// Encode the result using BASE64 to produce C2
	C2 := b64.StdEncoding.EncodeToString(ciphertext)

	// Compute `Sig`:

	// 1. The sender concatenates `C1` and `C2` to form a string `toSign`.
	toSign := C1 + C2

	// 2. The sender decodes its private signing key `sigSK`.
	// 3. The sender signs the string `toSign` using ECDSA with P-256 under key `sigSK`, and encodes the resulting signature using BASE64 to produce `Sig`.
	result := ECDSASign([]byte(toSign), globalPrivKey)

	Sig := b64.StdEncoding.EncodeToString(result)

	payload := map[string]string{
		"C1":  C1,
		"C2":  C2,
		"Sig": Sig,
	}

	res, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	return res
}

// Decrypt a list of messages in place
func decryptMessages(messageArray []MessageStruct) {
	// TODO: IMPLEMENT
	for i := range messageArray {
		if messageArray[i].Payload != "" {
			senderPubKey, err := getPublicKeyFromServer(messageArray[i].From)
			if err != nil {
				log.Printf("Failed to get public key for user %s: %v\n", messageArray[i].From, err)
				continue
			}

			decryptedMessage, err := decryptMessage(messageArray[i].Payload, messageArray[i].From, senderPubKey, &globalPrivKey)
			if err != nil {
				log.Printf("Failed to decrypt message from %s: %v\n", messageArray[i].From, err)
				continue
			}

			messageArray[i].decrypted = string(decryptedMessage)
			//send receipts
			sendMessageToServer(username, messageArray[i].From, nil, 1)
		}
	}
}

// Download any attachments in a message list
func downloadAttachments(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		return
	}

	os.Mkdir(attachmentsDir, 0755)

	// Iterate through the array, checking for attachments
	for i := 0; i < len(messageArray); i++ {
		fmt.Printf("222222222222, url: %s", messageArray[i].url)
		if messageArray[i].url != "" {
			// Make a random filename
			randBytes := make([]byte, 16)
			rand.Read(randBytes)
			localPath := filepath.Join(attachmentsDir, "attachment_"+hex.EncodeToString(randBytes)+".dat")

			parts := strings.Split(messageArray[i].decrypted, "?")
			key := strings.TrimPrefix(parts[1], "KEY=")
			hash := strings.TrimPrefix(parts[2], "H=")

			fmt.Printf("11111111111111")
			// Decrypt attachment
			// Downloads and decrypts an attachment from a given URL using the specified key and verifies the hash.
			err := downloadFileFromServer(messageArray[i].url, localPath, key, hash)
			if err == nil {
				messageArray[i].localPath = localPath
				fmt.Printf("Attachment from %s downloaded successfully to %s\n", messageArray[i].From, localPath)
			} else {
				fmt.Println(err)
			}

		}
	}
}

// Print a list of message structs
func printMessageList(messageArray []MessageStruct) {
	if len(messageArray) == 0 {
		fmt.Println("You have no new messages.")
		return
	}

	fmt.Printf("You have %d new messages\n-----------------------------\n\n", len(messageArray))
	// Iterate through the array, printing each message
	for i := 0; i < len(messageArray); i++ {
		if messageArray[i].ReceiptID != 0 {
			fmt.Printf("Read receipt\n")
			continue
		}

		fmt.Printf("From: %s\n\n", messageArray[i].From)

		fmt.Printf(messageArray[i].decrypted)
		if messageArray[i].localPath != "" {
			fmt.Printf("\n\tFile downloaded to %s\n", messageArray[i].localPath)
		} else if messageArray[i].url != "" {
			fmt.Printf("\n\tAttachment download failed\n")
		}
		fmt.Printf("\n-----------------------------\n\n")
	}
}

// Print a list of user structs
func printUserList(userArray []UserStruct) {
	if len(userArray) == 0 {
		fmt.Println("There are no users on the server.")
		return
	}

	fmt.Printf("The following users were detected on the server (* indicates recently active):\n")

	// Get current Unix time
	timestamp := time.Now().Unix()

	// Iterate through the array, printing each message
	for i := 0; i < len(userArray); i++ {
		if int64(userArray[i].CheckedTime) > int64(timestamp-1200) {
			fmt.Printf("* ")
		} else {
			fmt.Printf("  ")
		}

		fmt.Printf("%s\n", userArray[i].Username)
	}
	fmt.Printf("\n")
}

func getTempFilePath() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), "ENCFILE_"+hex.EncodeToString(randBytes)+".dat")
}

// Generate a fresh public key struct, containing encryption and signing keys
func generatePublicKey() (PubKeyStruct, PrivKeyStruct, error) {
	var pubKey PubKeyStruct
	var privKey PrivKeyStruct

	// TODO: IMPLEMENT

	// Generate a random scalar `a` between `0` and `q-1` (inclusive).
	a, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Use [PKCS8 encoding] to encode `a` as `encSK`.
	encSK, err := x509.MarshalPKCS8PrivateKey(a)
	if err != nil {
		panic(err)
	}

	//Use [RFC 5208] to encode `pk` as `encPK`.
	encPK, err := x509.MarshalPKIXPublicKey(a.PublicKey())
	if err != nil {
		panic(err)
	}

	privKey.EncSK = b64.StdEncoding.EncodeToString(encSK)
	pubKey.EncPK = b64.StdEncoding.EncodeToString(encPK)

	// Generate a random scalar `b` between `0` and `q-1` (inclusive).
	b, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Use [PKCS8 encoding] to encode `b` as `sigSK`.
	sigSK, err := x509.MarshalPKCS8PrivateKey(b)
	if err != nil {
		panic(err)
	}

	//Use [RFC 5208] to encode `pk` as `sigPK`.
	sigPK, err := x509.MarshalPKIXPublicKey(b.PublicKey())
	if err != nil {
		panic(err)
	}

	privKey.SigSK = b64.StdEncoding.EncodeToString(sigSK)
	pubKey.SigPK = b64.StdEncoding.EncodeToString(sigPK)

	return pubKey, privKey, nil
}

func main() {

	running := true
	reader := bufio.NewReader(os.Stdin)

	flag.IntVar(&serverPort, "port", 8080, "port for the server")
	flag.StringVar(&serverDomain, "domain", "localhost", "domain name for the server")
	flag.StringVar(&username, "username", "alice", "login username")
	flag.StringVar(&password, "password", "abc", "login password")
	flag.StringVar(&attachmentsDir, "attachdir", "./JMESSAGE_DOWNLOADS", "attachments directory (default is ./JMESSAGE_DOWNLOADS)")
	flag.BoolVar(&noTLS, "notls", false, "use HTTP instead of HTTPS")
	flag.BoolVar(&strictTLS, "stricttls", false, "don't accept self-signed certificates from the server (default accepts them)")
	flag.BoolVar(&doUserRegister, "reg", false, "register a new username and password")
	flag.BoolVar(&headlessMode, "headless", false, "run in headless mode")
	flag.Parse()

	// Set the server protocol to http or https
	if noTLS == false {
		serverProtocol = "https"
	} else {
		serverProtocol = "http"
	}

	// If self-signed certificates are allowed, enable weak TLS certificate validation globally
	if strictTLS == false {
		fmt.Println("Security warning: TLS certificate validation is disabled!")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Set up the server domain and port
	serverDomainAndPort = serverDomain + ":" + strconv.Itoa(serverPort)

	// If we are registering a new username, let's do that first
	if doUserRegister == true {
		fmt.Println("Registering new user...")
		err := registerUserWithServer(username, password)
		if err != nil {
			fmt.Println("Unable to register username with server (user may already exist)")
		}
	}

	// Connect and log in to the server
	fmt.Print("Logging in to server... ")
	newAPIkey, err := serverLogin(username, password)
	if err != nil {
		fmt.Println("Unable to connect to server, exiting.")
		os.Exit(1)
	}
	fmt.Println("success!")
	apiKey = newAPIkey

	// Generate a fresh public key, then upload it to the server
	globalPubKey, globalPrivKey, err = generatePublicKey()
	_ = globalPrivKey // This suppresses a Golang "unused variable" error
	if err != nil {
		fmt.Println("Unable to generate public key, exiting.")
		os.Exit(1)
	}

	err = registerPublicKeyWithServer(username, globalPubKey)
	if err != nil {
		fmt.Println("Unable to register public key with server, exiting.")
		os.Exit(1)
	}

	// Main command loop
	fmt.Println("Jmessage Go Client, enter command or help")
	for running == true {
		var input string
		var err error

		// If we're not in headless mode, read a command in
		if headlessMode == false {
			fmt.Print("> ")

			input, err = reader.ReadString('\n')
			if err != nil {
				fmt.Println("An error occured while reading input. Please try again", err)
			}
		} else {
			// Headless mode: we always sleep and then "GET"
			time.Sleep(time.Duration(100) * time.Millisecond)
			input = "GET"
		}

		parts := strings.Split(input, " ")
		//fmt.Println("got command: " + parts[0])
		switch strings.ToUpper(strings.TrimSpace(parts[0])) {
		case "SEND":
			if len(parts) < 2 {
				fmt.Println("Correct usage: send <username>")
			} else {
				err = doReadAndSendMessage(strings.TrimSpace(parts[1]), "")
				if err != nil {
					fmt.Println("--- ERROR: message send failed")
				} else {
					fmt.Println("--- message sent successfully!")
				}
			}
		case "GET":
			messageList, err := getMessagesFromServer()
			if err != nil {
				fmt.Print("Unable to fetch messages: ")
				fmt.Print(err)
			} else {
				downloadAttachments(messageList)
				printMessageList(messageList)
			}
		case "LIST":
			userList, err := getUserListFromServer()
			if err != nil {
				fmt.Print("Unable to fetch user list: ")
				fmt.Print(err)
			} else {
				printUserList(userList)
			}
		case "ATTACH":
			if len(parts) < 3 {
				fmt.Println("Correct usage: attach <username> <filename>")
			} else {
				// TODO: IMPLEMENT
				recipient := strings.TrimSpace(parts[1])
				filename := strings.TrimSpace(parts[2])
				tempFilePath := getTempFilePath()
				encryptedMessage, FileURL, err := encryptAttachment(filename, tempFilePath)
				if err != nil {
					fmt.Printf("Unable to encrypt attachment: %v\n", err)
					break
				}

				// Send the structured plaintext as a message
				err = sendAttachmentToServer(recipient, encryptedMessage, FileURL)
				if err != nil {
					fmt.Println("--- ERROR: attachment send failed")
				} else {
					fmt.Println("--- attachment sent successfully!")
				}

				// Clean up the temporary encrypted file
				os.Remove(tempFilePath)
			}
		case "QUIT":
			running = false
		case "HELP":
			fmt.Println("Commands are:\n\tsend <username> - send a message\n\tget - get new messages\n\tlist - print a list of all users\n\tquit - exit")

		default:
			fmt.Println("Unrecognized command")
		}
	}
}
