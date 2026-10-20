package c2engine

// Storage - SQLite persistence (compared against available reverse-engineering evidence; parity remains to be verified against tests for eSxbx2zKVifD.ZSeQgw1dB4ft).
//
// All SQL statements below are DECODED from the original binary's garble-
// encrypted string builders (see .re/SQL_SCHEMA.txt):
//
//	CREATE TABLE ...      FUN_011aef60 (1873-byte DAT-indexed swap+XOR, const 0x32)
//	select * from clients order by Id;     FUN_01199fc0 (34B subtract-array)
//	select * from listeners order by Id;   FUN_0119aaa0 (36B XOR-array)
//	select * from tunnels order by Id;     FUN_011aee00 (DAT-indexed swap+XOR, const 0x1b)
//	INSERT OR REPLACE INTO tunnels (...) VALUES (?,...);  FUN_011a7a20 (e8c0 chain key 0x52)
//
// Table/column layout is the decoded schema; Store* use INSERT OR REPLACE
// (same pattern as the decoded tunnels INSERT), Load* use the decoded SELECTs.

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// 解码自 FUN_011aef60 的完整建表语句（四张表：clients/tunnels/hosts/listeners）。
const decodedCreateTables = `
	CREATE TABLE IF NOT EXISTS clients (
		Id INTEGER PRIMARY KEY,
		IsConnect BOOLEAN,
		VerifyKey TEXT,
		Tp TEXT,
		Addr TEXT,
		Remark TEXT,
		Status BOOLEAN,
		LocalIP TEXT,
		UserName TEXT,
		HostName TEXT,
		Location TEXT,
		OsName TEXT,
		ProcessName TEXT,
		PingCheckTime INTEGER,
		RateLimit INTEGER,
		InletFlow INTEGER,
		ExportFlow INTEGER,
		FlowLimit INTEGER,
		NoStore BOOLEAN,
		NoDisplay BOOLEAN,
		MaxConn INTEGER,
		NowConn INTEGER
	);
	CREATE TABLE IF NOT EXISTS tunnels (
		Id INTEGER PRIMARY KEY,
		Port INTEGER,
		ServerIp TEXT,
		Mode TEXT,
		Status BOOLEAN,
		RunStatus BOOLEAN,
		ClientId INTEGER,
		Ports TEXT,
		InletFlow INTEGER,
		ExportFlow INTEGER,
		FlowLimit INTEGER,
		Username TEXT,
		Password TEXT,
		Remark TEXT,
		TargetAddr TEXT,
		NoStore BOOLEAN,
		LocalPath TEXT,
		StripPre TEXT,
		HealthCheckTimeout INTEGER,
		HealthMaxFail INTEGER,
		HealthCheckInterval INTEGER,
		HealthNextTime DATETIME,
		HttpHealthUrl TEXT,
		HealthCheckType TEXT,
		HealthCheckTarget TEXT
	);
	CREATE TABLE IF NOT EXISTS hosts (
		Id INTEGER PRIMARY KEY,
		Host TEXT,
		HeaderChange TEXT,
		HostChange TEXT,
		Location TEXT,
		Remark TEXT,
		Scheme TEXT,
		CertFilePath TEXT,
		KeyFilePath TEXT,
		NoStore BOOLEAN,
		IsClose BOOLEAN,
		InletFlow INTEGER,
		ExportFlow INTEGER,
		FlowLimit INTEGER,
		ClientId INTEGER,
		TargetStr TEXT,
		HealthCheckTimeout INTEGER,
		HealthMaxFail INTEGER,
		HealthCheckInterval INTEGER,
		HealthNextTime DATETIME,
		HttpHealthUrl TEXT,
		HealthCheckType TEXT,
		HealthCheckTarget TEXT
	);
	CREATE TABLE IF NOT EXISTS listeners (
		Id INTEGER PRIMARY KEY,
		Status BOOLEAN,
		ListenAddr TEXT,
		ConnectAddr TEXT,
		Remark TEXT,
		Mode TEXT,
		Vkey TEXT,
		EncryptSalt TEXT,
		DisconnectTimeout INTEGER,
		PingInterval INTEGER,
		DNSDomain TEXT,
		PublicDNS TEXT,
		MaxDNSsize INTEGER,
		OssUrl TEXT,
		NoStore BOOLEAN
	);
`

// 解码自 FUN_01199fc0（34B 减数组）。
const decodedSelectClients = `select * from clients order by Id;`

// 解码自 FUN_0119aaa0（36B XOR 数组）。
const decodedSelectListeners = `select * from listeners order by Id;`

// 解码自 FUN_011aee00（DAT 索引交换 XOR const 0x1b）。
const decodedSelectTunnels = `select * from tunnels order by Id;`

// 解码自 FUN_011a7a20（e8c0 链 key 0x52）——与建表列序逐列一致。
const decodedInsertTunnels = `INSERT OR REPLACE INTO tunnels (Id, Port, ServerIp, Mode, Status, RunStatus, ClientId, Ports, InletFlow, ExportFlow, FlowLimit, Username, Password, Remark, TargetAddr, NoStore, LocalPath, StripPre, HealthCheckTimeout, HealthMaxFail, HealthCheckInterval, HealthNextTime, HttpHealthUrl, HealthCheckType, HealthCheckTarget) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// clients/hosts/listeners 的 INSERT 与 tunnels 同构（格式已由 tunnels INSERT
// 确认；列序由建表 schema 决定）。
const decodedInsertClients = `INSERT OR REPLACE INTO clients (Id, IsConnect, VerifyKey, Tp, Addr, Remark, Status, LocalIP, UserName, HostName, Location, OsName, ProcessName, PingCheckTime, RateLimit, InletFlow, ExportFlow, FlowLimit, NoStore, NoDisplay, MaxConn, NowConn) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const decodedInsertHosts = `INSERT OR REPLACE INTO hosts (Id, Host, HeaderChange, HostChange, Location, Remark, Scheme, CertFilePath, KeyFilePath, NoStore, IsClose, InletFlow, ExportFlow, FlowLimit, ClientId, TargetStr, HealthCheckTimeout, HealthMaxFail, HealthCheckInterval, HealthNextTime, HttpHealthUrl, HealthCheckType, HealthCheckTarget) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const decodedInsertListeners = `INSERT OR REPLACE INTO listeners (Id, Status, ListenAddr, ConnectAddr, Remark, Mode, Vkey, EncryptSalt, DisconnectTimeout, PingInterval, DNSDomain, PublicDNS, MaxDNSsize, OssUrl, NoStore) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const decodedSelectHosts = `select * from hosts order by Id;`

// Storage handles SQLite persistence of engine data.
type Storage struct {
	db *sql.DB
}

// Close closes the underlying SQLite connection.
func (s *Storage) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// NewStorage opens (or creates) the SQLite database and applies the decoded
// schema. The DB file path mirrors the original binary's db/data.db.
func NewStorage(basePath string) *Storage {
	if basePath == "" {
		basePath = "db/data.db"
	}
	if dir := filepath.Dir(basePath); dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	db, err := sql.Open("sqlite", basePath)
	if err != nil {
		Logf("Warning: failed to open sqlite %s: %v", basePath, err)
		return &Storage{}
	}
	if _, err := db.Exec(decodedCreateTables); err != nil {
		Logf("Warning: failed to create tables in %s: %v", basePath, err)
	}
	return &Storage{db: db}
}

// InitDbFile initializes the database file (original binary method name).
func (s *Storage) InitDbFile() error {
	return nil
}

// --- clients ---

// StoreClients persists the client list (INSERT OR REPLACE, decoded columns).
func (s *Storage) StoreClients(clients map[int64]*Client) {
	if s.db == nil {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(decodedInsertClients)
	if err != nil {
		return
	}
	defer stmt.Close()
	for _, c := range clients {
		flowInlet, flowExport, flowLimit := int64(0), int64(0), int64(0)
		if c.Flow != nil {
			flowInlet, flowExport = c.Flow.Inlet, c.Flow.Export
			flowLimit = c.Flow.ImportFlow
		}
		if _, err := stmt.Exec(c.ID, c.IsConnect, c.VerifyKey, c.Type, c.Addr,
			c.Remark, c.Status, c.LocalIP, c.UserName, c.HostName, c.Location,
			c.OsName, c.ProcessName, c.PingCheckTime, c.RateLimit, flowInlet,
			flowExport, flowLimit, c.NoStore, c.NoDisplay, c.MaxConn, c.NowConn); err != nil {
			Logf("Warning: store client %d: %v", c.ID, err)
		}
	}
	_ = tx.Commit()
}

// LoadClients loads clients with the decoded SELECT (column order = schema).
func (s *Storage) LoadClients(clients map[int64]*Client, seq *int64) error {
	if s.db == nil {
		return fmt.Errorf("storage not initialized")
	}
	rows, err := s.db.Query(decodedSelectClients)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var c Client
		var inlet, export, limit int64
		if err := rows.Scan(&c.ID, &c.IsConnect, &c.VerifyKey, &c.Type, &c.Addr,
			&c.Remark, &c.Status, &c.LocalIP, &c.UserName, &c.HostName, &c.Location,
			&c.OsName, &c.ProcessName, &c.PingCheckTime, &c.RateLimit, &inlet,
			&export, &limit, &c.NoStore, &c.NoDisplay, &c.MaxConn, &c.NowConn); err != nil {
			return err
		}
		c.Flow = &Flow{Inlet: inlet, Export: export, ImportFlow: limit, ExportFlow: export}
		c.tunnels = make(map[int64]bool)
		c.Hosts = make(map[int64]bool)
		clients[c.ID] = &c
		if c.ID > *seq {
			*seq = c.ID
		}
	}
	return rows.Err()
}

// --- listeners ---

// StoreListeners persists the listener list.
func (s *Storage) StoreListeners(listeners map[int64]*Listener) {
	if s.db == nil {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(decodedInsertListeners)
	if err != nil {
		return
	}
	defer stmt.Close()
	for _, l := range listeners {
		if _, err := stmt.Exec(l.ID, l.Status, l.ListenAddr, l.ConnectAddr,
			l.Remark, l.Mode, l.VerifyKey, l.EncryptSalt, l.DisconnectTimeout,
			l.PingInterval, l.DNSDomain, l.PublicDNS, l.MaxDNSsize, l.OssUrl,
			l.NoStore); err != nil {
			Logf("Warning: store listener %d: %v", l.ID, err)
		}
	}
	_ = tx.Commit()
}

// LoadListeners loads listeners with the decoded SELECT.
func (s *Storage) LoadListeners(listeners map[int64]*Listener, seq *int64) error {
	if s.db == nil {
		return fmt.Errorf("storage not initialized")
	}
	rows, err := s.db.Query(decodedSelectListeners)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var l Listener
		if err := rows.Scan(&l.ID, &l.Status, &l.ListenAddr, &l.ConnectAddr,
			&l.Remark, &l.Mode, &l.VerifyKey, &l.EncryptSalt, &l.DisconnectTimeout,
			&l.PingInterval, &l.DNSDomain, &l.PublicDNS, &l.MaxDNSsize, &l.OssUrl,
			&l.NoStore); err != nil {
			return err
		}
		listeners[l.ID] = &l
		if l.ID > *seq {
			*seq = l.ID
		}
	}
	return rows.Err()
}

// --- hosts ---

// StoreHosts persists the host list.
func (s *Storage) StoreHosts(hosts map[int64]*Host) {
	if s.db == nil {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(decodedInsertHosts)
	if err != nil {
		return
	}
	defer stmt.Close()
	for _, h := range hosts {
		inlet, export, limit := int64(0), int64(0), int64(0)
		if h.Flow != nil {
			inlet, export = h.Flow.Inlet, h.Flow.Export
			limit = h.Flow.ImportFlow
		}
		if _, err := stmt.Exec(h.ID, h.Host, "", "", "", h.Remark, h.Scheme,
			"", "", h.NoStore, false, inlet, export, limit, h.ClientID,
			h.TargetStr, 0, 0, 0, time.Time{}, "", "", ""); err != nil {
			Logf("Warning: store host %d: %v", h.ID, err)
		}
	}
	_ = tx.Commit()
}

// LoadHosts loads hosts with the decoded SELECT.
func (s *Storage) LoadHosts(hosts map[int64]*Host, seq *int64) error {
	if s.db == nil {
		return fmt.Errorf("storage not initialized")
	}
	rows, err := s.db.Query(decodedSelectHosts)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var h Host
		var inlet, export, limit int64
		var headerChange, hostChange, location, remark, cert, key string
		var noStore, isClose bool
		var hcTimeout, hcMaxFail, hcInterval int64
		var hcNext time.Time
		var hcURL, hcType, hcTarget string
		if err := rows.Scan(&h.ID, &h.Host, &headerChange, &hostChange, &location,
			&remark, &h.Scheme, &cert, &key, &noStore, &isClose, &inlet, &export,
			&limit, &h.ClientID, &h.TargetStr, &hcTimeout, &hcMaxFail, &hcInterval,
			&hcNext, &hcURL, &hcType, &hcTarget); err != nil {
			return err
		}
		h.Flow = &Flow{Inlet: inlet, Export: export, ImportFlow: limit, ExportFlow: export}
		hosts[h.ID] = &h
		if h.ID > *seq {
			*seq = h.ID
		}
	}
	return rows.Err()
}

// --- tasks (persisted into the tunnels table per the binary) ---

// StoreTasks persists tasks. The original binary stores the task records in
// the tunnels table (LoadTaskFromSqlFile = select * from tunnels) — the
// decoded INSERT OR REPLACE INTO tunnels is used with the task's fields
// mapped onto the tunnel columns (Id/ClientId/Status/RunStatus/Remark/Ports).
func (s *Storage) StoreTasks(tasks map[int64]*Task) {
	if s.db == nil {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(decodedInsertTunnels)
	if err != nil {
		return
	}
	defer stmt.Close()
	for _, t := range tasks {
		if _, err := stmt.Exec(t.ID, 0, "", t.Status, false, false, t.ClientID,
			t.Command, 0, 0, int64(t.Timeout), "", "", t.Result, "", t.Timeout == 0,
			"", "", 0, 0, 0, time.Time{}, "", "", ""); err != nil {
			Logf("Warning: store task %d: %v", t.ID, err)
		}
	}
	_ = tx.Commit()
}

// LoadTasks loads tasks from the tunnels table (decoded SELECT).
func (s *Storage) LoadTasks(tasks map[int64]*Task, seq *int64) error {
	if s.db == nil {
		return fmt.Errorf("storage not initialized")
	}
	rows, err := s.db.Query(decodedSelectTunnels)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var t Task
		var port, status, runStatus int
		var serverIP, mode, ports, username, password, remark, targetAddr string
		var noStore bool
		var localPath, stripPre string
		var hcTimeout, hcMaxFail, hcInterval, inlet, export, limit int64
		var hcNext time.Time
		var hcURL, hcType, hcTarget string
		if err := rows.Scan(&t.ID, &port, &serverIP, &mode, &status, &runStatus,
			&t.ClientID, &ports, &inlet, &export, &limit, &username, &password,
			&remark, &targetAddr, &noStore, &localPath, &stripPre, &hcTimeout,
			&hcMaxFail, &hcInterval, &hcNext, &hcURL, &hcType, &hcTarget); err != nil {
			return err
		}
		t.Command = ports
		t.Result = remark
		t.Status = mode
		tasks[t.ID] = &t
		if t.ID > *seq {
			*seq = t.ID
		}
	}
	return rows.Err()
}

// --- deletes ---

// DelClient removes a client's persisted row.
func (s *Storage) DelClient(id int64) {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`delete from clients where Id = ?`, id)
}

// DelHost removes a host's persisted row.
func (s *Storage) DelHost(id int64) {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`delete from hosts where Id = ?`, id)
}

// DelTunnel removes a tunnel's persisted row.
func (s *Storage) DelTunnel(id int64) {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`delete from tunnels where Id = ?`, id)
}

// DelListener removes a listener's persisted row.
func (s *Storage) DelListener(id int64) {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`delete from listeners where Id = ?`, id)
}

// StoreClientsToJsonFile is the original binary's method name
// (eSxbx2zKVifD.(*ZSeQgw1dB4ft).StoreClientsToJsonFile); persisted via SQLite.
func (s *Storage) StoreClientsToJsonFile(clients map[int64]*Client) {
	s.StoreClients(clients)
}

// StoreListenerToJsonFile is the original binary's method name.
func (s *Storage) StoreListenerToJsonFile(listeners map[int64]*Listener) {
	s.StoreListeners(listeners)
}

// StoreHostToJsonFile is the original binary's method name.
func (s *Storage) StoreHostToJsonFile(hosts map[int64]*Host) {
	s.StoreHosts(hosts)
}

// StoreTasksToJsonFile is the original binary's method name.
func (s *Storage) StoreTasksToJsonFile(tasks map[int64]*Task) {
	s.StoreTasks(tasks)
}

// LoadClientFromSqlFile is the original binary's method name.
func (s *Storage) LoadClientFromSqlFile(clients map[int64]*Client, seq *int64) error {
	return s.LoadClients(clients, seq)
}

// LoadListenerFromSqlFile is the original binary's method name.
func (s *Storage) LoadListenerFromSqlFile(listeners map[int64]*Listener, seq *int64) error {
	return s.LoadListeners(listeners, seq)
}

// LoadHostFromSqlFile is the original binary's method name.
func (s *Storage) LoadHostFromSqlFile(hosts map[int64]*Host, seq *int64) error {
	return s.LoadHosts(hosts, seq)
}

// LoadTaskFromSqlFile is the original binary's method name.
func (s *Storage) LoadTaskFromSqlFile(tasks map[int64]*Task, seq *int64) error {
	return s.LoadTasks(tasks, seq)
}
